#include "taps/taps_api.h"
#include "buffer/heap_block_pool.h"

namespace taps{

// The only BlockPoolFactory shipped today: builds today's default HeapBlockPool.
// Used whenever the app constructs a TransportServices without one of its own.
namespace {
class DefaultBlockPoolFactory : public BlockPoolFactory {
public:
    std::unique_ptr<BlockPool> make() const override {
        return std::make_unique<HeapBlockPool>();
    }
};
}  // namespace

TransportServices::TransportServices(asio::io_context& ctx,
                                     std::shared_ptr<BlockPoolFactory> pool_factory)
    : io_context_(ctx),
      pool_factory_(pool_factory ? std::move(pool_factory)
                                  : std::make_shared<DefaultBlockPoolFactory>()) {}

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
                                                         pool_factory_);
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
                                                         std::move(properties), std::move(security),
                                                         pool_factory_);
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
