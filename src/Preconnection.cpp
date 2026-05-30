#include "taps/taps_api.h"
#include <asio/use_awaitable.hpp>
#include <asio/steady_timer.hpp>

namespace taps {

// ============================================================================
// Preconnection Implementation
// ============================================================================

asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::initiate() {
    if (remote_endpoints_.size() == 1) {
        co_return co_await initiate_with_single_endpoint();
    }
    
    co_return co_await happy_eyeballs_racing();
}


asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::initiate_with_single_endpoint() {
    auto asio_endpoints = co_await remote_endpoints_.at(0).resolve(io_context_);
    
    if (asio_endpoints.empty()) {
        co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, 
                                          "Failed to resolve remote endpoint"));
    }
    
    auto& endpoint = asio_endpoints[0];
    
    if (transport_properties_.requires_reliable_transport()) {
        try {
            auto tcp_conn = std::make_unique<TCPConnection>(io_context_, endpoint);
            tcp_conn->set_framer(std::make_unique<NoOpFramer>());
            auto conn_result = co_await tcp_conn->connect();
            
            co_return std::unique_ptr<Connection>(std::move(tcp_conn));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
        }
    } else {
        asio::ip::udp::endpoint udp_endpoint(endpoint.address(), endpoint.port());
        
        try {
            auto udp_conn = std::make_unique<ActiveUDPConnection>(io_context_, udp_endpoint);
            udp_conn->set_framer(std::make_unique<NoOpFramer>());
            
            co_return std::unique_ptr<Connection>(std::move(udp_conn));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
        }
    }
}

asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::happy_eyeballs_racing() {
    std::vector<asio::ip::tcp::endpoint> all_endpoints;
    
    try {
        auto primary_resolved = co_await remote_endpoints_.at(0).resolve(io_context_);
        all_endpoints.insert(all_endpoints.end(), primary_resolved.begin(), primary_resolved.end());
        
        for (std::size_t i = 1; i < remote_endpoints_.size(); ++i) {
            auto resolved = co_await remote_endpoints_[i].resolve(io_context_);
            all_endpoints.insert(all_endpoints.end(), resolved.begin(), resolved.end());
        }
        
        if (all_endpoints.empty()) {
            co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, 
                                              "No addresses resolved"));
        }
        
    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, e.what()));
    }
    
    co_return co_await race_connections(all_endpoints);
}


/// Happy Eyeballs (RFC 8305) — staggered sequential attempt.
///
/// Tries endpoints sequentially with a 250ms stagger between attempts
/// (RFC 8305 §5 recommendation). The first endpoint is tried immediately;
/// subsequent endpoints are tried after a delay only if the previous one
/// hasn't succeeded.
///
/// This implementation is:
/// - Thread-safe on single-threaded io_context (no shared mutable state)
/// - Free of resource leaks (each failed connection is aborted before
///   attempting the next one)
/// - Simple to reason about correctness
/// - Effective for the typical 1-3 endpoint case (IPv4/IPv6 dual-stack)
///
/// For scenarios with many endpoints requiring true parallel racing,
/// a future implementation using asio::experimental::parallel_group
/// would be preferable but requires careful lifetime management of
/// Connection objects across coroutines.
asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::race_connections(
    const std::vector<asio::ip::tcp::endpoint>& endpoints) {
    
    using namespace std::chrono_literals;

    if (endpoints.empty()) {
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, 
                                          "No endpoints to connect to"));
    }

    TAPSError last_error{ErrorType::CONNECTION_FAILED, "No endpoints attempted"};

    for (std::size_t i = 0; i < endpoints.size(); ++i) {
        auto conn = std::make_unique<TCPConnection>(io_context_, endpoints[i]);
        conn->set_framer(std::make_unique<NoOpFramer>());

        // Try connecting to this endpoint
        auto connect_result = co_await conn->connect();

        if (connect_result) {
            // Success — return the established connection
            co_return std::unique_ptr<Connection>(conn.release());
        }

        // Failed — record error, abort this connection, stagger before next
        last_error = connect_result.error();
        co_await conn->abort();

        // RFC 8305 §5: wait 250ms before trying the next address family
        if (i + 1 < endpoints.size()) {
            asio::steady_timer stagger(io_context_, 250ms);
            co_await stagger.async_wait(asio::use_awaitable);
        }
    }

    // All endpoints failed
    co_return std::unexpected(TAPSError(ErrorType::CONNECTION_TIMEOUT,
                                      "All " + std::to_string(endpoints.size()) + 
                                      " connection attempts failed: " + last_error.message()));
}

} // namespace taps