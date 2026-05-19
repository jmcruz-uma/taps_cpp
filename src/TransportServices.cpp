#include "taps/taps_api.h"

namespace taps{

// ============================================================================
// TransportServices Implementation
// ============================================================================

asio::awaitable<Result<std::unique_ptr<Listener>>> TransportServices::listen(
    LocalEndpoint local, TransportProperties properties, SecurityParameters security) {
    
    // Determine protocol based on properties
    if (properties.requires_reliable_transport()) {
        // TCP Listener
        try {
            auto listener = std::make_unique<TCPListener>(io_context_, std::move(local), 
                                                         std::move(properties), std::move(security));
            auto listen_result = co_await listener->listen();
            if (!listen_result) {
                co_return std::unexpected(listen_result.error());
            }
            co_return std::unique_ptr<Listener>(std::move(listener));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::INTERNAL_ERROR, e.what()));
        }
    } else {
        // UDP Listener
        try {
            auto listener = std::make_unique<UDPListener>(io_context_, std::move(local),
                                                         std::move(properties), std::move(security));
            auto listen_result = co_await listener->listen();
            if (!listen_result) {
                co_return std::unexpected(listen_result.error());
            }
            co_return std::unique_ptr<Listener>(std::move(listener));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::INTERNAL_ERROR, e.what()));
        }
    }
}


}