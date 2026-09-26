
#include "taps/taps_api.h"
#include "transport/io_error.h"
#include "security/security_provider.h"
#ifdef TAPS_WITH_TLS
#include "security/tls_provider.h"
#endif
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <algorithm>

namespace taps {

// Out-of-line: security_provider_ is a unique_ptr to a forward-declared type.
TCPListener::~TCPListener() = default;


// ============================================================================
// TCP Listener Implementation
// ============================================================================

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
        
        // RFC 9622 Section 7.2: a Listener's EstablishmentError concerns the Listener
        // itself (configuration, resolution, policy). An incoming connection that
        // fails before it is established (reset before accept, failed TLS handshake)
        // is not delivered, and the Listener keeps waiting for the next one.
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

            if (security_parameters_.is_enabled()) {
#ifdef TAPS_WITH_TLS
                if (!security_provider_) {
                    auto provider = TlsProvider::create(security_parameters_,
                                                        TlsProvider::Role::Server);
                    if (!provider) {
                        co_await connection->abort();
                        co_return std::unexpected(provider.error());
                    }
                    security_provider_ = std::move(*provider);
                }
                auto secured = co_await connection->apply_security(*security_provider_, "");
                if (!secured) {
                    co_await connection->abort();
                    continue;
                }
#else
                co_await connection->abort();
                co_return std::unexpected(TAPSError{
                    ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::NO_CANDIDATES,
                    "SecurityParameters request TLS but this build has TAPS_WITH_TLS=OFF"});
#endif
            }

            co_return std::unique_ptr<Connection>(std::move(connection));
        }
    }
    
    asio::awaitable<Result<void>> TCPListener::stop() {
        if (!is_listening_) {
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