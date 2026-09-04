#include "taps/taps_api.h"
#include <asio/experimental/parallel_group.hpp>
#include <asio/experimental/awaitable_operators.hpp>

namespace taps{

// ============================================================================
// Preconnection Implementation
// ============================================================================
asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::initiate() {
    // Si solo tenemos un endpoint, usar el flujo simple actual
    if (remote_endpoints_.size() == 1) {
        co_return co_await initiate_with_single_endpoint();
    }
    
    // Happy Eyeballs racing con múltiples endpoints
    co_return co_await happy_eyeballs_racing();
}


asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::initiate_with_single_endpoint() {
    // Simple implementation - try direct connection first
    auto asio_endpoints = co_await remote_endpoints_.at(0).resolve(io_context_);
    
    if (asio_endpoints.empty()) {
        co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, 
                                          "Failed to resolve remote endpoint"));
    }
    
    // For now, just try the first endpoint
    auto& endpoint = asio_endpoints[0];
    
    // Determine protocol based on transport properties
    if (transport_properties_.requires_reliable_transport()) {
        // Use TCP
        try {
            auto tcp_conn = std::make_unique<TCPConnection>(io_context_, endpoint, pool_factory_);

            auto conn_result = co_await tcp_conn->connect();
            
            co_return std::unique_ptr<Connection>(std::move(tcp_conn));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
        }
    } else {
        // Convert TCP endpoint to UDP
        asio::ip::udp::endpoint udp_endpoint(endpoint.address(), endpoint.port());
        
        try {
            auto udp_conn = std::make_unique<ActiveUDPConnection>(io_context_, udp_endpoint, pool_factory_);

            co_return std::unique_ptr<Connection>(std::move(udp_conn));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
        }
    }
}

asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::happy_eyeballs_racing() {
    std::vector<asio::ip::tcp::endpoint> all_endpoints;
    
    // Resolver todos los endpoints (remote_endpoint_ + remote_endpoints_)
    try {
        auto primary_resolved = co_await remote_endpoints_.at(0).resolve(io_context_);
        all_endpoints.insert(all_endpoints.end(), primary_resolved.begin(), primary_resolved.end());
        
        for (const auto& remote : remote_endpoints_) {
            auto resolved = co_await remote.resolve(io_context_);
            all_endpoints.insert(all_endpoints.end(), resolved.begin(), resolved.end());
        }
        
        if (all_endpoints.empty()) {
            co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, 
                                              "No addresses resolved"));
        }
        
    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, e.what()));
    }
    
    // Happy Eyeballs racing
    co_return co_await race_connections(all_endpoints);
}



asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::race_connections(
    const std::vector<asio::ip::tcp::endpoint>& endpoints) {
    
    using namespace std::chrono_literals;
    
    // Shared state para el racing
    struct RaceState {
        std::atomic<bool> finished{false};
        std::mutex winner_mutex;
        std::unique_ptr<Connection> winner;
        std::size_t winner_index = 0;
        TAPSError last_error{ErrorType::CONNECTION_FAILED, "No connections attempted"};
    };
    
    auto race_state = std::make_shared<RaceState>();
    std::vector<std::unique_ptr<TCPConnection>> connections;
    connections.reserve(endpoints.size());
    
    // Crear todas las conexiones
    for (const auto& endpoint : endpoints) {
        connections.push_back(std::make_unique<TCPConnection>(io_context_, endpoint, pool_factory_));
    }
    
    try {
        // Lanzar todas las conexiones concurrentemente
        for (std::size_t i = 0; i < connections.size(); ++i) {
            asio::co_spawn(io_context_,
                [race_state, i, conn = std::move(connections[i])]() mutable -> asio::awaitable<void> {
                    try {
                        auto connect_result = co_await conn->connect();
                        
                        if (connect_result) {
                            // Intentar ser el ganador
                            std::lock_guard<std::mutex> lock(race_state->winner_mutex);
                            if (!race_state->finished.exchange(true)) {
                                race_state->winner = std::move(conn);
                                race_state->winner_index = i;
                            }
                        } else {
                            // Actualizar último error
                            std::lock_guard<std::mutex> lock(race_state->winner_mutex);
                            race_state->last_error = connect_result.error();
                        }
                    } catch (const std::exception& e) {
                        std::lock_guard<std::mutex> lock(race_state->winner_mutex);
                        race_state->last_error = TAPSError(ErrorType::CONNECTION_FAILED, e.what());
                    }
                    co_return;
                },
                asio::detached
            );
        }
        
        // Esperar con timeout
        auto deadline = std::chrono::steady_clock::now() + 10s;
        constexpr auto poll_interval = 50ms;
        
        while (!race_state->finished.load() && std::chrono::steady_clock::now() < deadline) {
            auto timer = asio::steady_timer(io_context_);
            timer.expires_after(poll_interval);
            co_await timer.async_wait(asio::use_awaitable);
        }
        
        // Verificar resultado
        {
            std::lock_guard<std::mutex> lock(race_state->winner_mutex);
            if (race_state->winner) {
                co_return std::move(race_state->winner);
            } else if (std::chrono::steady_clock::now() >= deadline) {
                co_return std::unexpected(TAPSError(ErrorType::CONNECTION_TIMEOUT,
                                                  "All connection attempts timed out"));
            } else {
                co_return std::unexpected(race_state->last_error);
            }
        }
        
    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
    }
}

}