#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "udp_demux.h"
#include "buffer/block_chain.h"
#include "buffer/message_block_pool.h"
#include "transport/io_error.h"
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/dispatch.hpp>
#include <asio/error.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iterator>
#include <memory>

namespace taps {

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

// ============================================================================
// UDPDemux
// ============================================================================

UDPDemux::UDPDemux(asio::io_context& ctx, std::unique_ptr<MessageBlockPool> pool)
: socket_(ctx)
, strand_(asio::make_strand(ctx))
, pool_(std::move(pool))
, sweep_timer_(strand_)
, accept_channel_(ctx.get_executor(), 100)
{}

UDPDemux::~UDPDemux() = default;

Result<void> UDPDemux::start(const asio::ip::udp::endpoint& local) {
    asio::error_code ec;
    socket_.open(local.protocol(), ec);
    if (!ec)
        socket_.set_option(asio::ip::udp::socket::reuse_address(true), ec);
    if (!ec)
        socket_.bind(local, ec);
    if (ec) {
        asio::error_code ignored;
        socket_.close(ignored);
        return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, ec));
    }
    // Each coroutine holds a reference until the socket closes or the timer is
    // cancelled (shut_down_if_unused()).
    asio::co_spawn(strand_, [self = shared_from_this()] { return self->receive_loop(); },
                   asio::detached);
    asio::co_spawn(strand_, [self = shared_from_this()] { return self->sweep_loop(); },
                   asio::detached);
    return Result<void>{std::in_place};
}

asio::awaitable<void> UDPDemux::receive_loop() {
    asio::ip::udp::endpoint sender;
    for (;;) {
        BlockRef block = pool_->acquire();
        if (!block) {
            // At the live-block cap: read the datagram and drop it (UDP has no flow
            // control; the Mailboxes drop the oldest datagram for the same reason).
            std::array<std::byte, 1> sink;
            asio::error_code ec;
            co_await socket_.async_receive_from(asio::buffer(sink), sender,
                                                asio::redirect_error(asio::use_awaitable, ec));
            if (ec == asio::error::operation_aborted)
                co_return;
            continue;
        }
        asio::error_code ec;
        const std::size_t n = co_await socket_.async_receive_from(
            asio::buffer(block.writable_data(), block.capacity_after_begin()),
            sender, asio::redirect_error(asio::use_awaitable, ec));
        if (ec == asio::error::operation_aborted)
            co_return;                            // socket closed: nothing left to serve
        if (ec)
            continue;                             // transient receive error

        auto datagram = make_chain(pool_->resource());
        if (n > 0) {
            block.set_range(0, n);
            datagram->append(std::move(block));
        }

        const auto now = std::chrono::steady_clock::now();
        std::shared_ptr<Mailbox> mailbox;
        if (auto it = index_.find(sender); it != index_.end()) {
            it->second->last_active = now;
            lru_.splice(lru_.begin(), lru_, it->second);     // move to most recent
            mailbox = it->second->mailbox;
        } else {
            if (!accepting_)
                continue;                         // no Listener: no new Connections
            if (index_.size() >= max_connections() && !lru_.empty())
                evict(std::prev(lru_.end()), Mailbox::CloseCause::displaced);
            mailbox = std::make_shared<Mailbox>(strand_, pool_->resource());
            lru_.push_front(Entry{sender, mailbox, now});
            index_.emplace(sender, lru_.begin());

            // Non-blocking: if accept() is not keeping up, drop the new source
            // rather than stall the demux for everyone.
            auto conn = std::make_unique<PassiveUDPConnection>(shared_from_this(), sender, mailbox);
            if (!accept_channel_.try_send(std::error_code{}, std::move(conn))) {
                // `conn` was not taken; its destructor releases the source.
                continue;
            }
        }
        mailbox->deliver(std::move(datagram));
    }
}

asio::awaitable<void> UDPDemux::sweep_loop() {
    for (;;) {
        sweep_timer_.expires_after(sweep_interval());
        asio::error_code ec;
        co_await sweep_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
            co_return;                            // cancelled by shut_down_if_unused()
        const auto cutoff = std::chrono::steady_clock::now() - idle_timeout();
        while (!lru_.empty() && lru_.back().last_active < cutoff)
            evict(std::prev(lru_.end()), Mailbox::CloseCause::idle);
        shut_down_if_unused();
    }
}

void UDPDemux::evict(Lru::iterator it, Mailbox::CloseCause cause) {
    it->mailbox->close(cause);                    // a waiting receive() fails with the cause
    index_.erase(it->source);
    lru_.erase(it);
}

void UDPDemux::shut_down_if_unused() {
    if (accepting_ || !index_.empty())
        return;
    asio::error_code ignored;
    socket_.close(ignored);                       // ends receive_loop()
    sweep_timer_.cancel();                        // ends sweep_loop()
}

asio::awaitable<Result<std::unique_ptr<Connection>>> UDPDemux::accept() {
    // The channel is not thread-safe: use it from strand_ only, like the receive loop.
    co_await asio::dispatch(strand_, asio::use_awaitable);
    auto [ec, conn] = co_await accept_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
    if (ec)
        co_return std::unexpected(TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INVALID_STATE,
                                            "Listener stopped"));
    conn->state_ = ConnectionState::ESTABLISHED;
    co_return Result<std::unique_ptr<Connection>>(std::move(conn));
}

void UDPDemux::stop_accepting() {
    asio::post(strand_, [self = shared_from_this()] {
        self->accepting_ = false;
        self->accept_channel_.close();            // a pending accept() fails
        self->shut_down_if_unused();
    });
}

void UDPDemux::release(const asio::ip::udp::endpoint& source, const Mailbox* mailbox) {
    asio::post(strand_, [self = shared_from_this(), source, mailbox] {
        auto it = self->index_.find(source);
        if (it != self->index_.end() && it->second->mailbox.get() == mailbox)
            self->evict(it->second, Mailbox::CloseCause::owner);
        self->shut_down_if_unused();
    });
}

// ============================================================================
// UDPListener
// ============================================================================

UDPListener::UDPListener(
    asio::io_context& ctx,
    LocalEndpoint local,
    TransportProperties properties,
    SecurityParameters security,
    MessageMemoryConfig memory)
: io_context_(ctx)
, demux_(std::make_shared<UDPDemux>(
      ctx, std::make_unique<MessageBlockPool>(memory)))
{
    local_endpoint_       = std::move(local);
    transport_properties_ = std::move(properties);
    security_parameters_  = std::move(security);
}

// Existing Connections keep the demultiplexer alive; this only stops accepting.
UDPListener::~UDPListener() {
    if (is_listening_)
        demux_->stop_accepting();
}

asio::awaitable<Result<void>> UDPListener::listen() {
    // No security protocol for datagrams here: requested security cannot be
    // fulfilled for listening (RFC 9622 Section 7.2), rather than silently not applied.
    if (security_parameters_.is_enabled())
        co_return std::unexpected(TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::NO_CANDIDATES,
                                            "security was requested, but no available protocol secures an unreliable transport"));
    try {
        auto endpoints = co_await local_endpoint_.resolve(io_context_);
        if (endpoints.empty()) {
            co_return std::unexpected(
                TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::RESOLUTION_FAILED,
                         "Failed to resolve local endpoint"));
        }
        auto started = demux_->start(asio::ip::udp::endpoint(endpoints[0].address(), endpoints[0].port()));
        if (!started)
            co_return started;
        is_listening_ = true;
        co_return Result<void>{std::in_place};
    } catch (const std::system_error& e) {
        co_return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, e.code()));
    } catch (const std::exception& e) {
        co_return std::unexpected(
            TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, e.what()));
    }
}

asio::awaitable<Result<std::unique_ptr<Connection>>> UDPListener::accept() {
    if (!is_listening_) {
        co_return std::unexpected(
            TAPSError(ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INVALID_STATE, "Not listening"));
    }
    auto demux = demux_;                          // the Listener may go while this waits
    co_return co_await demux->accept();
}

// Stops accepting new sources; the Connections already accepted keep working.
asio::awaitable<Result<void>> UDPListener::stop() {
    if (is_listening_) {
        is_listening_ = false;
        demux_->stop_accepting();
    }
    co_return Result<void>{std::in_place};
}

} // namespace taps
