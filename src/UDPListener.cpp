#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "buffer/block_chain.h"
#include "buffer/block_pool.h"
#include <asio/co_spawn.hpp>
#include <asio/error.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>
#include <chrono>
#include <cstdlib>
#include <iterator>
#include <memory>

namespace taps {

// ============================================================================
// UDPListener
//
// Invariant: UDPListener outlives all PassiveUDPConnection instances.
// on_close callbacks may safely capture `this`.
//
// One bound socket, one receive loop on strand_. Incoming datagrams are
// demultiplexed by source endpoint into per-connection Mailboxes. The demux
// table is a bounded LRU: a new source beyond kMaxConnections evicts the
// least-recently-active one, and an idle sweep evicts sources quiet for longer
// than kIdleTimeout. This keeps memory bounded under a spoofed-source flood
// without attempting address validation (out of scope).
// ============================================================================

namespace {
constexpr std::size_t kMaxConnections = 1024;
constexpr auto        kIdleTimeout    = std::chrono::seconds(30);
constexpr auto        kSweepInterval  = std::chrono::seconds(5);

// Overridable for testing / tuning; falls back to the constants above.
std::size_t env_or(const char* name, std::size_t def) {
    if (const char* s = std::getenv(name)) {
        const unsigned long long v = std::strtoull(s, nullptr, 10);
        if (v != 0) return static_cast<std::size_t>(v);
    }
    return def;
}
std::size_t max_connections() { return env_or("TAPS_UDP_MAX_CONNS", kMaxConnections); }
std::chrono::seconds idle_timeout() {
    return std::chrono::seconds(env_or("TAPS_UDP_IDLE_SECS",
                                       static_cast<std::size_t>(kIdleTimeout.count())));
}
std::chrono::seconds sweep_interval() {
    return std::chrono::seconds(env_or("TAPS_UDP_SWEEP_SECS",
                                       static_cast<std::size_t>(kSweepInterval.count())));
}
}  // namespace

UDPListener::UDPListener(
    asio::io_context& ctx,
    LocalEndpoint local,
    TransportProperties properties,
    SecurityParameters security)
: io_context_(ctx)
, socket_(ctx)
, strand_(asio::make_strand(ctx))
, accept_channel_(io_context_.get_executor(), 100)
, block_pool_(std::make_unique<BlockPool>())
, sweep_timer_(strand_)
{
    local_endpoint_       = std::move(local);
    transport_properties_ = std::move(properties);
    security_parameters_  = std::move(security);
}

UDPListener::~UDPListener() = default;

// --- demux helpers (strand_) -------------------------------------------------

std::shared_ptr<Mailbox>
UDPListener::touch_or_create(const asio::ip::udp::endpoint& sender, bool& is_new) {
    const auto now = std::chrono::steady_clock::now();

    if (auto mit = index_.find(sender); mit != index_.end()) {
        auto node = mit->second;
        node->last_active = now;
        lru_.splice(lru_.begin(), lru_, node);   // move to most-recent
        is_new = false;
        return node->mailbox;
    }

    if (index_.size() >= max_connections() && !lru_.empty())
        evict(std::prev(lru_.end()));            // drop least-recently-active

    auto mailbox = std::make_shared<Mailbox>(strand_);
    lru_.push_front(Conn{sender, mailbox, now});
    index_.emplace(sender, lru_.begin());
    is_new = true;
    return mailbox;
}

void UDPListener::evict(std::list<Conn>::iterator it) {
    it->mailbox->close();                        // waiting receive() -> closed error
    index_.erase(it->endpoint);
    lru_.erase(it);
}

asio::awaitable<void> UDPListener::sweep_loop() {
    for (;;) {
        sweep_timer_.expires_after(sweep_interval());
        asio::error_code ec;
        co_await sweep_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
            co_return;                           // cancelled by stop()
        const auto cutoff = std::chrono::steady_clock::now() - idle_timeout();
        while (!lru_.empty() && lru_.back().last_active < cutoff)
            evict(std::prev(lru_.end()));
    }
}

// --- listen ----------------------------------------------------------------

asio::awaitable<Result<void>> UDPListener::listen() {
    try {
        auto endpoints = co_await local_endpoint_.resolve(io_context_);
        if (endpoints.empty()) {
            co_return std::unexpected(
                TAPSError(ErrorType::RESOLUTION_FAILED,
                         "Failed to resolve local endpoint"));
        }

        asio::ip::udp::endpoint udp_ep(endpoints[0].address(), endpoints[0].port());

        socket_.open(udp_ep.protocol());
        socket_.set_option(asio::ip::udp::socket::reuse_address(true));
        socket_.bind(udp_ep);

        is_listening_ = true;

        // Receive loop and idle sweep both run on strand_, so the demux table and
        // every Mailbox are single-threaded with no locking.
        asio::co_spawn(
            strand_,
            [this]() -> asio::awaitable<void> {
                asio::ip::udp::endpoint sender;

                for (;;) {
                    BlockRef block = block_pool_->acquire();
                    asio::error_code ec;
                    std::size_t n = co_await socket_.async_receive_from(
                        asio::buffer(block.writable_data(), block.capacity_after_begin()),
                        sender,
                        asio::redirect_error(asio::use_awaitable, ec));

                    if (ec == asio::error::operation_aborted)
                        co_return;                // socket closed by stop()
                    if (ec)
                        continue;                 // transient receive error

                    auto datagram = std::make_shared<BlockChain>();
                    if (n > 0) {
                        block.set_range(0, n);
                        datagram->append(std::move(block));
                    }

                    bool is_new = false;
                    std::shared_ptr<Mailbox> mailbox = touch_or_create(sender, is_new);

                    if (is_new) {
                        auto conn = std::make_unique<PassiveUDPConnection>(
                            socket_, sender, mailbox);
                        conn->on_close_ = [this, sender] {
                            asio::post(strand_, [this, sender] {
                                if (auto mit = index_.find(sender); mit != index_.end())
                                    evict(mit->second);
                            });
                        };

                        // Non-blocking: if accept() is not keeping up, drop the new
                        // source rather than stall the demux for everyone (it can
                        // reconnect once the app catches up).
                        if (!accept_channel_.try_send(std::error_code{}, std::move(conn))) {
                            if (auto mit = index_.find(sender); mit != index_.end())
                                evict(mit->second);
                            continue;
                        }
                    }

                    mailbox->deliver(std::move(datagram));
                }
            },
            asio::detached);

        asio::co_spawn(strand_, sweep_loop(), asio::detached);

        co_return Result<void>{std::in_place};

    } catch (const std::exception& e) {
        co_return std::unexpected(
            TAPSError(ErrorType::INTERNAL_ERROR, e.what()));
    }
}

asio::awaitable<Result<std::unique_ptr<Connection>>> UDPListener::accept() {
    if (!is_listening_) {
        co_return std::unexpected(
            TAPSError(ErrorType::INVALID_CONFIGURATION, "Not listening"));
    }

    auto [ec, conn] =
        co_await accept_channel_.async_receive(asio::as_tuple(asio::use_awaitable));

    if (ec) {
        co_return std::unexpected(
            TAPSError(ErrorType::INTERNAL_ERROR, ec.message()));
    }
    conn->state_ = ConnectionState::ESTABLISHED;
    co_return Result<std::unique_ptr<Connection>>(std::move(conn));
}

asio::awaitable<Result<void>> UDPListener::stop() {
    socket_.close();          // wakes the receive loop with operation_aborted
    sweep_timer_.cancel();
    is_listening_ = false;
    index_.clear();
    lru_.clear();
    co_return Result<void>{std::in_place};
}

} // namespace taps
