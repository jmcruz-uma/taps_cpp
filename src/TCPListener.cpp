
#include "taps/taps_api.h"
#include "security/security_provider.h"
#ifdef TAPS_WITH_TLS
#include "security/tls_provider.h"
#endif
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
                        std::shared_ptr<BlockPoolFactory> pool_factory)
        : io_context_(ctx), acceptor_(ctx), pool_factory_(std::move(pool_factory)){
            local_endpoint_ = std::move(local);
            transport_properties_ = std::move(properties);
            security_parameters_ = std::move(security);
        }
    
asio::awaitable<Result<void>> TCPListener::listen() {
        if (is_listening_) {
            co_return std::unexpected(TAPSError{ErrorType::INVALID_CONFIGURATION, 
                                              "Already listening"});
        }
        
        try {
            // Resolve local endpoint
            auto endpoints = co_await local_endpoint_.resolve(io_context_);
            if (endpoints.empty()) {
                co_return std::unexpected(TAPSError{ErrorType::RESOLUTION_FAILED, 
                                                  "Failed to resolve local endpoint"});
            }
            
            // Try to bind to resolved endpoints
            bool bound = false;
            for (const auto& endpoint : endpoints) {
                try {
                    acceptor_.open(endpoint.protocol());
                    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
                    acceptor_.bind(endpoint);
                    acceptor_.listen();
                    bound = true;
                    break;
                } catch (const std::system_error&) {
                    // Try next endpoint
                    if (acceptor_.is_open()) {
                        acceptor_.close();
                    }
                }
            }
            
            if (!bound) {
                co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                                  "Failed to bind to any endpoint"});
            }
            
            is_listening_ = true;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              e.code().message()});
        }
    }
    
    asio::awaitable<Result<std::unique_ptr<Connection>>> TCPListener::accept() {
        if (!is_listening_) {
            co_return std::unexpected(TAPSError{ErrorType::INVALID_CONFIGURATION, 
                                              "Not listening"});
        }
        
        try {
            auto socket = co_await acceptor_.async_accept(asio::use_awaitable);

            // Create connection from accepted socket
            auto connection = std::make_unique<TCPConnection>(std::move(socket), pool_factory_);

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
                    co_return std::unexpected(secured.error());
                }
#else
                co_await connection->abort();
                co_return std::unexpected(TAPSError{
                    ErrorType::INVALID_CONFIGURATION,
                    "SecurityParameters request TLS but this build has TAPS_WITH_TLS=OFF"});
#endif
            }

            co_return std::unique_ptr<Connection>(std::move(connection));

        } catch (const std::system_error& e) {
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              e.code().message()});
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
            co_return std::unexpected(TAPSError{ErrorType::INTERNAL_ERROR, 
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