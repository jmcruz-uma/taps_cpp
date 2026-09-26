#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "taps/message_framer.h"
#include "buffer/block_chain.h"
#include "buffer/block_pool.h"
#include "buffer/heap_block_pool.h"
#include "transport/io_error.h"
#include <asio/co_spawn.hpp>
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
TAPSError udp_failure(ErrorEvent event, const std::system_error& e, bool aborted) {
    if (e.code() == asio::error::operation_aborted)
        return cancelled(event, aborted);
    return io_error(event, e.code());
}

}  // namespace

// ============================================================================
// PassiveUDPConnection Implementation
// ============================================================================

PassiveUDPConnection::PassiveUDPConnection(
    asio::ip::udp::socket& socket,
    asio::ip::udp::endpoint remote,
    std::shared_ptr<Mailbox> mailbox)
: socket_(socket)
, remote_endpoint_(remote)
, mailbox_(std::move(mailbox))
{
    state_ = ConnectionState::ESTABLISHING;
}

PassiveUDPConnection::~PassiveUDPConnection() {
    if (mailbox_)
        mailbox_->close();
}

asio::awaitable<Result<void>>
PassiveUDPConnection::send(const Message& message) {
    try {
        const auto body = message.as_bytes();
        if (framer_) {
            std::array<std::byte, 64> hdr;
            assert(framer_->max_header_size() <= hdr.size());
            const std::size_t hn = framer_->write_header(message, hdr);
            const std::array<asio::const_buffer, 2> iov{
                asio::buffer(hdr.data(), hn),
                asio::buffer(body.data(), body.size())};
            co_await socket_.async_send_to(iov, remote_endpoint_, asio::use_awaitable);
        } else {
            co_await socket_.async_send_to(
                asio::buffer(body.data(), body.size()), remote_endpoint_,
                asio::use_awaitable);
        }

        co_return Result<void>{std::in_place};
    } catch (const std::system_error& e) {
        co_return std::unexpected(udp_failure(ErrorEvent::SEND_ERROR, e, aborted_));
    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INTERNAL_ERROR, e.what()));
    }
}

asio::awaitable<Result<Message>>
PassiveUDPConnection::receive() {
    try {
        // One datagram = one single-block chain from the listener's pool; no copy.
        std::shared_ptr<BlockChain> datagram = co_await mailbox_->receive();
        co_return Message(std::move(datagram), MessageContext{}, /*end_of_message=*/true);
    } catch (const std::system_error&) {
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
}

asio::awaitable<Result<void>>
PassiveUDPConnection::close() {
    state_ = ConnectionState::CLOSED;
    //mailbox_->close();
    //mailbox_.reset();
    if (on_close_) {
        on_close_();
    }
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
    auto local = socket_.local_endpoint();
    return LocalEndpoint(
        local.address().to_string(),
        local.port());
}

std::size_t PassiveUDPConnection::datagrams_dropped() const noexcept {
    return mailbox_ ? mailbox_->dropped() : 0;
}


// ============================================================================
// ActiveUDPConnection Implementation
// ============================================================================

ActiveUDPConnection::ActiveUDPConnection(asio::io_context& ctx, asio::ip::udp::endpoint endpoint,
                                         std::shared_ptr<BlockPoolFactory> pool_factory)
    : socket_(ctx), remote_endpoint_(endpoint),
      block_pool_(pool_factory ? pool_factory->make() : std::make_unique<HeapBlockPool>()) {
    state_ = ConnectionState::ESTABLISHING;
}

ActiveUDPConnection::~ActiveUDPConnection() = default;


asio::awaitable<Result<void>> ActiveUDPConnection::send(const Message& message) {
    if (state_ == ConnectionState::CLOSED) {
        co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INVALID_STATE,
                                            "Connection is closed"));
    }
    
    try {
        // Open socket if not already open
        if (!socket_.is_open()) {
            socket_.open(remote_endpoint_.protocol());
            state_ = ConnectionState::ESTABLISHED;
        }
        
        const auto body = message.as_bytes();
        std::array<std::byte, 64> hdr;
        std::size_t hn = 0;
        if (framer_) {
            assert(framer_->max_header_size() <= hdr.size());
            hn = framer_->write_header(message, hdr);
        }
        const std::array<asio::const_buffer, 2> iov{
            asio::buffer(hdr.data(), hn),
            asio::buffer(body.data(), body.size())};

        const std::size_t bytes_sent = co_await socket_.async_send_to(
            iov, remote_endpoint_, asio::use_awaitable);

        if (bytes_sent != hn + body.size()) {
            co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::PROTOCOL_FAILED,
                                                "Partial send occurred"));
        }

        co_return std::expected<void, TAPSError>{std::in_place};
        
    } catch (const std::system_error& e) {
        co_return std::unexpected(udp_failure(ErrorEvent::SEND_ERROR, e, aborted_));
    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INTERNAL_ERROR, e.what()));
    }
}

asio::awaitable<Result<Message>> ActiveUDPConnection::receive() {
    if (state_ == ConnectionState::CLOSED) {
        co_return std::unexpected(TAPSError(ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE,
                                            "Connection is closed"));
    }
    
    if (state_ == ConnectionState::ESTABLISHING) {
        co_return std::unexpected(TAPSError(ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE,
                                            "This connection needs to send before receive any data"));
    }

    try {
        // Read straight into a pooled block; deliver the datagram as a
        // single-block chain, recycled when the Message is dropped. No copy.
        BlockRef block = block_pool_->acquire();
        asio::ip::udp::endpoint sender_endpoint;

        const std::size_t n = co_await socket_.async_receive_from(
            asio::buffer(block.writable_data(), block.capacity_after_begin()),
            sender_endpoint, asio::use_awaitable);

        auto chain = std::make_shared<BlockChain>();
        if (n > 0) {
            block.set_range(0, n);
            chain->append(std::move(block));
        }
        co_return Message(std::move(chain), MessageContext{}, /*end_of_message=*/true);

    } catch (const std::system_error& e) {
        co_return std::unexpected(udp_failure(ErrorEvent::RECEIVE_ERROR, e, aborted_));
    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorEvent::RECEIVE_ERROR, ErrorReason::INTERNAL_ERROR, e.what()));
    }
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