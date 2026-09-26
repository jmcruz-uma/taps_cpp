
#include "taps/taps_api.h"
#include "transport/io_error.h"
#include "secure_acceptor.h"
#include "security/security_provider.h"
#ifdef TAPS_WITH_TLS
#include "security/tls_provider.h"
#endif
#include <asio/redirect_error.hpp>
#include <asio/post.hpp>
#include <asio/dispatch.hpp>
#include <asio/detached.hpp>
#include <asio/co_spawn.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <algorithm>

namespace taps {

// ============================================================================
// SecureAcceptor
// ============================================================================

SecureAcceptor::SecureAcceptor(asio::ip::tcp::acceptor acceptor,
                               std::unique_ptr<SecurityProvider> provider,
                               MessageMemoryConfig memory)
    : acceptor_(std::move(acceptor)),
      strand_(asio::make_strand(acceptor_.get_executor())),
      provider_(std::move(provider)),
      memory_(memory),
      ready_(acceptor_.get_executor(), 100) {}

void SecureAcceptor::start() {
    asio::co_spawn(strand_, [self = shared_from_this()] { return self->accept_loop(); },
                   asio::detached);
}

asio::awaitable<void> SecureAcceptor::accept_loop() {
    for (;;) {
        asio::error_code ec;
        auto socket = co_await acceptor_.async_accept(asio::redirect_error(asio::use_awaitable, ec));
        if (ec == asio::error::operation_aborted)
            co_return;                                    // stopped
        if (ec == asio::error::connection_aborted)
            continue;                                     // reset before it was accepted
        if (ec) {
            // Reported to accept(); the loop goes on (the channel bounds how many wait).
            co_await ready_.async_send(ec, nullptr, asio::as_tuple(asio::use_awaitable));
            continue;
        }
        asio::co_spawn(acceptor_.get_executor(),
                       [self = shared_from_this(), s = std::move(socket)]() mutable {
                           return self->secure(std::move(s));
                       },
                       asio::detached);
    }
}

asio::awaitable<void> SecureAcceptor::secure(asio::ip::tcp::socket socket) {
    auto connection = std::make_unique<TCPConnection>(std::move(socket), memory_);
    auto secured = co_await connection->apply_security(*provider_, "");
    if (!secured) {
        co_await connection->abort();
        co_return;
    }
    co_await asio::dispatch(strand_, asio::use_awaitable);
    co_await ready_.async_send(std::error_code{}, std::move(connection),
                               asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<Result<std::unique_ptr<Connection>>> SecureAcceptor::accept() {
    // The channel is not thread-safe: use it from strand_ only, like the accept loop.
    co_await asio::dispatch(strand_, asio::use_awaitable);
    auto [ec, connection] = co_await ready_.async_receive(asio::as_tuple(asio::use_awaitable));
    if (ec == asio::experimental::error::channel_closed ||
        ec == asio::experimental::error::channel_cancelled)
        co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INVALID_STATE,
                                            "Listener stopped"});
    if (ec)
        co_return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, ec));
    co_return std::unique_ptr<Connection>(std::move(connection));
}

void SecureAcceptor::stop() {
    asio::post(strand_, [self = shared_from_this()] {
        asio::error_code ignored;
        self->acceptor_.close(ignored);                   // ends the accept loop
        self->ready_.close();                             // a pending accept() fails
    });
}

asio::ip::tcp::endpoint SecureAcceptor::local_endpoint() const {
    asio::error_code ec;
    return acceptor_.local_endpoint(ec);
}

// ============================================================================
// TCP Listener Implementation
// ============================================================================

// Accepted Connections do not depend on the Listener; with security, handshakes in
// flight finish on their own (see SecureAcceptor).
TCPListener::~TCPListener() {
    if (secure_)
        secure_->stop();
}

TCPListener::TCPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties,
                        SecurityParameters security,
                        MessageMemoryConfig memory)
        : io_context_(ctx), acceptor_(ctx), memory_(memory){
            local_endpoint_ = std::move(local);
            transport_properties_ = std::move(properties);
            security_parameters_ = std::move(security);
        }
    
asio::awaitable<Result<void>> TCPListener::listen() {
        if (is_listening_) {
            co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INVALID_STATE,
                                                "Already listening"});
        }
        
        try {
            // Resolve local endpoint
            auto endpoints = co_await local_endpoint_.resolve(io_context_);
            if (endpoints.empty()) {
                co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::RESOLUTION_FAILED,
                                                    "Failed to resolve local endpoint"});
            }
            
            // Try to bind to resolved endpoints
            bool bound = false;
            std::error_code last_ec;
            for (const auto& endpoint : endpoints) {
                try {
                    acceptor_.open(endpoint.protocol());
                    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
                    acceptor_.bind(endpoint);
                    acceptor_.listen();
                    bound = true;
                    break;
                } catch (const std::system_error& e) {
                    // Try next endpoint
                    last_ec = e.code();
                    if (acceptor_.is_open()) {
                        acceptor_.close();
                    }
                }
            }
            
            if (!bound) {
                co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, reason_from(last_ec),
                                                    "Failed to bind to any endpoint: " + last_ec.message()});
            }

            // With security, connections are secured in parallel by a SecureAcceptor,
            // which takes over the acceptor. The security configuration is checked
            // here: a Listener that cannot fulfil it does not listen (RFC 9622 Section 7.2).
            if (security_parameters_.is_enabled()) {
#ifdef TAPS_WITH_TLS
                auto provider = TlsProvider::create(security_parameters_, TlsProvider::Role::Server);
                if (!provider) {
                    acceptor_.close();
                    co_return std::unexpected(provider.error());
                }
                secure_ = std::make_shared<SecureAcceptor>(std::move(acceptor_), std::move(*provider), memory_);
                secure_->start();
#else
                acceptor_.close();
                co_return std::unexpected(TAPSError{
                    ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::NO_CANDIDATES,
                    "SecurityParameters request TLS but this build has TAPS_WITH_TLS=OFF"});
#endif
            }
            
            is_listening_ = true;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            co_return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, e.code()));
        }
    }
    
    asio::awaitable<Result<std::unique_ptr<Connection>>> TCPListener::accept() {
        if (!is_listening_) {
            co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INVALID_STATE,
                                                "Not listening"});
        }
        
        if (secure_) {
            auto secure = secure_;                        // the Listener may go while this waits
            co_return co_await secure->accept();
        }

        // RFC 9622 Section 7.2: a Listener's EstablishmentError concerns the Listener
        // itself (configuration, resolution, policy). An incoming connection that
        // fails before it is established (reset before accept) is not delivered, and
        // the Listener keeps waiting for the next one.
        for (;;) {
            asio::error_code ec;
            auto socket = co_await acceptor_.async_accept(asio::redirect_error(asio::use_awaitable, ec));
            if (ec == asio::error::connection_aborted)
                continue;
            if (ec == asio::error::operation_aborted)
                co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR,
                                                    ErrorReason::INVALID_STATE, "Listener stopped"});
            if (ec)
                co_return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, ec));

            auto connection = std::make_unique<TCPConnection>(std::move(socket), memory_);
            co_return std::unique_ptr<Connection>(std::move(connection));
        }
    }
    
    asio::awaitable<Result<void>> TCPListener::stop() {
        if (!is_listening_) {
            co_return std::expected<void, TAPSError>{std::in_place};
        }
        
        if (secure_) {
            secure_->stop();
            is_listening_ = false;
            co_return std::expected<void, TAPSError>{std::in_place};
        }
        try {
            acceptor_.close();
            is_listening_ = false;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, 
                                              e.code().message()});
        }
    }
    
    bool TCPListener::is_listening() const noexcept { 
        return is_listening_; 
    }
    
    LocalEndpoint TCPListener::get_local_endpoint() const {
        if (secure_) {
            const auto endpoint = secure_->local_endpoint();
            return LocalEndpoint(endpoint.address().to_string(), endpoint.port());
        }
        if (acceptor_.is_open()) {
            try {
                auto endpoint = acceptor_.local_endpoint();
                return LocalEndpoint(endpoint.address().to_string(), endpoint.port());
            } catch (const std::exception&) {
                // Fall through to return configured endpoint
            }
        }
        return local_endpoint_;
    }

} // namespace taps