#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "udp_demux.h"
#include "new_connection_limit.h"
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
#include <limits>
#include <memory>

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

namespace taps {

namespace {

// The most sources a UDP Listener's table holds: as many as the process may have
// file descriptors, read when a new source arrives (so a raised limit applies at
// once). Each passive Connection is meant to hold a descriptor of its own; this is
// what the process can afford, not a policy. Windows has no such limit to read.
std::size_t connection_ceiling() {
#if defined(_WIN32)
    return std::size_t{1} << 16;
#else
    rlimit lim{};
    if (::getrlimit(RLIMIT_NOFILE, &lim) != 0 || lim.rlim_cur == RLIM_INFINITY)
        return std::numeric_limits<std::size_t>::max();
    return static_cast<std::size_t>(lim.rlim_cur);
#endif
}

}  // namespace

// ============================================================================
// UDPDemux
// ============================================================================

UDPDemux::UDPDemux(asio::io_context& ctx, std::unique_ptr<MessageBlockPool> pool,
                   std::shared_ptr<NewConnectionLimit> limit)
: socket_(ctx)
, strand_(asio::make_strand(ctx))
, pool_(std::move(pool))
, limit_(std::move(limit))
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
    if (!ec)
        local_ = socket_.local_endpoint(ec);
    if (ec) {
        asio::error_code ignored;
        socket_.close(ignored);
        return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, ec));
    }
    // The loop holds a reference until the socket closes (shut_down_if_unused()).
    asio::co_spawn(strand_, [self = shared_from_this()] { return self->receive_loop(); },
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

        std::shared_ptr<Mailbox> mailbox;
        if (auto it = table_.find(sender); it != table_.end()) {
            mailbox = it->second;
        } else {
            if (!accepting_)
                continue;                         // no Listener: no new Connections
            if (table_.size() >= connection_ceiling())
                continue;                         // full: the new source is refused
            if (!limit_->take())
                continue;                         // new-connection limit at zero (RFC 9622 Section 7.2)
            mailbox = std::make_shared<Mailbox>(strand_, pool_->resource());
            table_.emplace(sender, mailbox);

            // Non-blocking: if accept() is not keeping up, drop the new source
            // rather than stall the demux for everyone.
            auto conn = std::make_unique<PassiveUDPConnection>(shared_from_this(), sender, mailbox);
            if (!accept_channel_.try_send(std::error_code{}, std::move(conn))) {
                // `conn` was not taken; its destructor releases the source.
                limit_->give_back();
                continue;
            }
        }
        mailbox->deliver(std::move(datagram));
    }
}

void UDPDemux::shut_down_if_unused() {
    if (accepting_ || !table_.empty())
        return;
    asio::error_code ignored;
    socket_.close(ignored);                       // ends receive_loop()
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

asio::awaitable<std::tuple<std::error_code, std::size_t>>
UDPDemux::send_to(const ConstBufferSequence& datagram, const asio::ip::udp::endpoint& to) {
    co_await asio::dispatch(strand_, asio::use_awaitable);
    co_return co_await socket_.async_send_to(datagram, to, asio::as_tuple(asio::use_awaitable));
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
        auto it = self->table_.find(source);
        if (it != self->table_.end() && it->second.get() == mailbox) {
            it->second->close();                  // a waiting receive() fails
            self->table_.erase(it);
        }
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
      ctx, std::make_unique<MessageBlockPool>(memory), new_connection_limit_))
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
