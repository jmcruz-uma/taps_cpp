#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "taps/message_framer.h"
#include "buffer/block_chain.h"
#include "buffer/message_block_pool.h"
#include "transport/io_error.h"
#include "transport/const_buffer_sequence.h"
#include "udp_demux.h"
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/dispatch.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <memory>

namespace taps {

namespace {

// An operation cancelled by the application: after abort() it is the
// CONNECTION_ERROR / LOCAL_ABORT of RFC 9622 Section 10; after close(), the
// Connection is simply no longer usable.
TAPSError cancelled(ErrorEvent event, bool aborted) {
    if (aborted)
        return TAPSError{ErrorEvent::CONNECTION_ERROR, ErrorReason::LOCAL_ABORT, "Connection aborted"};
    return TAPSError{event, ErrorReason::INVALID_STATE, "Connection closed locally"};
}

// A socket failure during send or receive. UDP ends a Connection only on Abort
// (RFC 9623 Section 10.3), so any other failure concerns this operation only.
// Not implemented yet: RFC 9623 Section 10.3 reports ICMP errors (e.g. port
// unreachable) as SoftError events. The sockets here are not connected, and on an
// unconnected socket Linux does not report ICMP errors by default (IP_RECVERR
// would be needed), so they are not seen at all.
TAPSError udp_failure(ErrorEvent event, const std::error_code& ec, bool aborted) {
    if (ec == asio::error::operation_aborted)
        return cancelled(event, aborted);
    return io_error(event, ec);
}

}  // namespace

// ============================================================================
// PassiveUDPConnection Implementation
// ============================================================================

PassiveUDPConnection::PassiveUDPConnection(
    std::shared_ptr<UDPDemux> demux,
    asio::ip::udp::endpoint remote,
    std::shared_ptr<Mailbox> mailbox)
: demux_(std::move(demux))
, remote_endpoint_(remote)
, mailbox_(std::move(mailbox))
{
    state_ = ConnectionState::ESTABLISHING;
}

// Destroyed without close(): the source still leaves the table, so a later
// datagram from it creates a new Connection (RFC 9623 Section 4.7.2).
PassiveUDPConnection::~PassiveUDPConnection() {
    release();
}

void PassiveUDPConnection::release() noexcept {
    if (released_)
        return;
    released_ = true;
    demux_->release(remote_endpoint_, mailbox_.get());
}

asio::awaitable<Result<void>>
PassiveUDPConnection::send(const Message& message) {
    if (state_ == ConnectionState::CLOSED) {
        co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INVALID_STATE,
                                            "Connection is closed"));
    }
    // Header + the Message as it is (a received one is sent from its blocks).
    std::array<std::byte, 64> hdr;
    std::size_t hn = 0;
    if (framer_) {
        assert(framer_->max_header_size() <= hdr.size());
        hn = framer_->write_header(message, hdr);
    }
    const ConstBufferSequence iov(std::span<const std::byte>(hdr.data(), hn), message);
    auto [ec, n] = co_await demux_->socket().async_send_to(iov, remote_endpoint_,
                                                          asio::as_tuple(asio::use_awaitable));
    if (ec)
        co_return std::unexpected(udp_failure(ErrorEvent::SEND_ERROR, ec, aborted_));
    co_return Result<void>{std::in_place};
}

asio::awaitable<Result<Message>>
PassiveUDPConnection::receive() {
    for (;;) {
        // The Mailbox belongs to the listener's strand: go there before each look.
        co_await asio::dispatch(mailbox_->executor(), asio::use_awaitable);
        // One datagram = one single-block chain from the listener's pool; no copy.
        if (auto datagram = mailbox_->try_pop())
            co_return Message(std::move(datagram), MessageContext{}, /*end_of_message=*/true);
        if (mailbox_->closed())
            break;
        co_await mailbox_->wait();
    }
    state_ = ConnectionState::CLOSED;
    switch (mailbox_->close_cause()) {
        case Mailbox::CloseCause::idle:
            co_return std::unexpected(TAPSError(ErrorEvent::CONNECTION_ERROR, ErrorReason::IDLE_TIMEOUT,
                                                "no traffic from the peer within the idle timeout"));
        case Mailbox::CloseCause::displaced:
            co_return std::unexpected(TAPSError(ErrorEvent::CONNECTION_ERROR, ErrorReason::RESOURCE_EXHAUSTED,
                                                "evicted: the listener's connection table is full"));
        case Mailbox::CloseCause::owner:
            break;
    }
    co_return std::unexpected(cancelled(ErrorEvent::RECEIVE_ERROR, aborted_));
}

asio::awaitable<Result<void>>
PassiveUDPConnection::close() {
    state_ = ConnectionState::CLOSED;
    release();                                  // a pending receive() fails with INVALID_STATE
    co_return Result<void>{std::in_place};
}

asio::awaitable<Result<void>>
PassiveUDPConnection::abort() {
    aborted_ = true;
    co_return co_await close();
}

RemoteEndpoint
PassiveUDPConnection::get_remote_endpoint() const {
    return RemoteEndpoint(
        remote_endpoint_.address().to_string(),
        remote_endpoint_.port());
}

LocalEndpoint
PassiveUDPConnection::get_local_endpoint() const {
    asio::error_code ec;
    const auto local = demux_->socket().local_endpoint(ec);
    if (ec)
        return LocalEndpoint{};
    return LocalEndpoint(local.address().to_string(), local.port());
}

std::size_t PassiveUDPConnection::datagrams_dropped() const noexcept {
    return mailbox_ ? mailbox_->dropped() : 0;
}


// ============================================================================
// ActiveUDPConnection Implementation
// ============================================================================

ActiveUDPConnection::ActiveUDPConnection(asio::io_context& ctx, asio::ip::udp::endpoint endpoint,
                                         const MessageMemoryConfig& memory)
    : socket_(ctx), remote_endpoint_(endpoint),
      block_pool_(std::make_unique<MessageBlockPool>(memory)) {
    state_ = ConnectionState::ESTABLISHING;
}

ActiveUDPConnection::~ActiveUDPConnection() = default;

Result<void> ActiveUDPConnection::open() {
    asio::error_code ec;
    socket_.open(remote_endpoint_.protocol(), ec);
    if (!ec)
        socket_.bind(asio::ip::udp::endpoint(remote_endpoint_.protocol(), 0), ec);
    if (ec)
        return std::unexpected(io_error(ErrorEvent::ESTABLISHMENT_ERROR, ec));
    state_ = ConnectionState::ESTABLISHED;
    return Result<void>{std::in_place};
}


asio::awaitable<Result<void>> ActiveUDPConnection::send(const Message& message) {
    if (state_ != ConnectionState::ESTABLISHED) {
        co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INVALID_STATE,
                                            "Connection not established"));
    }
    
    // Header + the Message as it is (a received one is sent from its blocks).
    std::array<std::byte, 64> hdr;
    std::size_t hn = 0;
    if (framer_) {
        assert(framer_->max_header_size() <= hdr.size());
        hn = framer_->write_header(message, hdr);
    }
    const ConstBufferSequence iov(std::span<const std::byte>(hdr.data(), hn), message);
    auto [ec, bytes_sent] = co_await socket_.async_send_to(iov, remote_endpoint_,
                                                           asio::as_tuple(asio::use_awaitable));
    if (ec)
        co_return std::unexpected(udp_failure(ErrorEvent::SEND_ERROR, ec, aborted_));
    if (bytes_sent != hn + message.size())
        co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::PROTOCOL_FAILED,
                                            "Partial send occurred"));
    co_return std::expected<void, TAPSError>{std::in_place};
}

asio::awaitable<Result<Message>> ActiveUDPConnection::receive() {
    if (state_ != ConnectionState::ESTABLISHED) {
        co_return std::unexpected(TAPSError(ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE,
                                            "Connection not established"));
    }
    

    // Read straight into a pooled block; deliver the datagram as a single-block
    // chain, recycled when the Message is dropped. No copy.
    BlockRef block = block_pool_->acquire();
    if (!block)
        co_return std::unexpected(TAPSError(ErrorEvent::RECEIVE_ERROR, ErrorReason::RESOURCE_EXHAUSTED,
                                            "receive block pool exhausted"));
    asio::ip::udp::endpoint sender_endpoint;
    auto [ec, n] = co_await socket_.async_receive_from(
        asio::buffer(block.writable_data(), block.capacity_after_begin()),
        sender_endpoint, asio::as_tuple(asio::use_awaitable));
    if (ec)
        co_return std::unexpected(udp_failure(ErrorEvent::RECEIVE_ERROR, ec, aborted_));

    auto chain = make_chain(block_pool_->resource());
    if (n > 0) {
        block.set_range(0, n);
        chain->append(std::move(block));
    }
    co_return Message(std::move(chain), MessageContext{}, /*end_of_message=*/true);
}

asio::awaitable<Result<void>> ActiveUDPConnection::close() {
    asio::error_code ec;
    if (socket_.is_open())
        socket_.close(ec);
    state_ = ConnectionState::CLOSED;
    if (ec)
        co_return std::unexpected(TAPSError(ErrorEvent::CONNECTION_ERROR, ErrorReason::INTERNAL_ERROR,
                                            ec.message()));
    co_return std::expected<void, TAPSError>{std::in_place};
}


asio::awaitable<Result<void>> ActiveUDPConnection::abort() {
    // RFC 9623 Section 10.3: like close(), but pending operations report
    // CONNECTION_ERROR / LOCAL_ABORT.
    aborted_ = true;
    co_return co_await close();
}

RemoteEndpoint ActiveUDPConnection::get_remote_endpoint() const {
    return RemoteEndpoint(remote_endpoint_.address().to_string(), remote_endpoint_.port());
}

LocalEndpoint ActiveUDPConnection::get_local_endpoint() const {
    if (socket_.is_open()) {
        auto local_ep = socket_.local_endpoint();
        return LocalEndpoint(local_ep.address().to_string(), local_ep.port());
    }
    return LocalEndpoint{};
}

} // namespace taps