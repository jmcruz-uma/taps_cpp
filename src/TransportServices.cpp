#include "taps/taps_api.h"

#include <memory_resource>

namespace taps{

std::pmr::pool_options message_pool_options() noexcept {
    std::pmr::pool_options options;
    options.max_blocks_per_chunk = 16;
    options.largest_required_pool_block = 64 * 1024;
    return options;
}

std::pmr::memory_resource* default_message_resource() {
    static std::pmr::unsynchronized_pool_resource resource(message_pool_options(),
                                                           std::pmr::new_delete_resource());
    return &resource;
}

TransportServices::TransportServices(asio::io_context& ctx, MessageMemoryConfig memory)
    : io_context_(ctx), memory_(memory) {
    if (!memory_.resource)
        memory_.resource = default_message_resource();
}

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
                                                         std::move(properties), std::move(security),
                                                         memory_);
            auto listen_result = co_await listener->listen();
            if (!listen_result) {
                co_return std::unexpected(listen_result.error());
            }
            co_return std::unique_ptr<Listener>(std::move(listener));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, e.what()));
        }
    } else {
        // UDP Listener
        try {
            auto listener = std::make_unique<UDPListener>(io_context_, std::move(local),
                                                         std::move(properties), std::move(security),
                                                         memory_);
            auto listen_result = co_await listener->listen();
            if (!listen_result) {
                co_return std::unexpected(listen_result.error());
            }
            co_return std::unique_ptr<Listener>(std::move(listener));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, e.what()));
        }
    }
}


}
