#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <bit>

namespace taps {

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
        std::vector<uint8_t> data;
        if (framer_)
            framer_->frame_message(message, data);
        else
            data.assign(message.data().begin(), message.data().end());

        co_await socket_.async_send_to(
            asio::buffer(data),
            remote_endpoint_,
            asio::use_awaitable);

        co_return Result<void>{std::in_place};
    } catch (const std::exception& e) {
        state_ = ConnectionState::ERROR;
        co_return std::unexpected(
            TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
    }
}

asio::awaitable<Result<Message>>
PassiveUDPConnection::receive() {
    try {
        auto data = co_await mailbox_->receive();
        co_return make_message(std::move(data));
    } catch (...) {
        state_ = ConnectionState::CLOSED;
        co_return std::unexpected(
            TAPSError(ErrorType::CONNECTION_FAILED,
                     "Connection closed"));
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


// ============================================================================
// ActiveUDPConnection Implementation
// ============================================================================

ActiveUDPConnection::ActiveUDPConnection(asio::io_context& ctx, asio::ip::udp::endpoint endpoint)
    : socket_(ctx), remote_endpoint_(endpoint){
    state_ = ConnectionState::ESTABLISHING;
}


asio::awaitable<Result<void>> ActiveUDPConnection::send(const Message& message) {
    if (state_ == ConnectionState::CLOSED || state_ == ConnectionState::ERROR) {
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, 
                                          "Connection is closed"));
    }
    
    try {
        // Open socket if not already open
        if (!socket_.is_open()) {
            socket_.open(remote_endpoint_.protocol());
            state_ = ConnectionState::ESTABLISHED;
        }
        
        std::vector<std::uint8_t> data_to_send;
        if (framer_) {
            framer_->frame_message(message, data_to_send);
        } else {
            data_to_send.assign(message.data().begin(), message.data().end());
        }

        auto bytes_sent = co_await socket_.async_send_to(
            asio::buffer(data_to_send),
            remote_endpoint_,
            asio::use_awaitable
        );

        if (bytes_sent != data_to_send.size()) {
            co_return std::unexpected(TAPSError(ErrorType::PROTOCOL_ERROR,
                                                "Partial send occurred"));
        }

        co_return std::expected<void, TAPSError>{std::in_place};
        
    } catch (const std::exception& e) {
        state_ = ConnectionState::ERROR;
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
    }
}

asio::awaitable<Result<Message>> ActiveUDPConnection::receive() {
    if (state_ == ConnectionState::CLOSED || state_ == ConnectionState::ERROR) {
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED,
                                          "Connection is closed"));
    }
    
    if (state_ == ConnectionState::ESTABLISHING) {
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED,
                                          "This connection needs to send before receive any data"));
    }

    try {
        std::vector<uint8_t> buffer(65536);
        asio::ip::udp::endpoint sender_endpoint;
        
        co_await socket_.async_receive_from(
                        asio::buffer(buffer), sender_endpoint, asio::use_awaitable);
       
        co_return make_message(std::move(buffer));
        
    } catch (const std::exception& e) {
        state_ = ConnectionState::ERROR;
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
    }
}

asio::awaitable<Result<void>> ActiveUDPConnection::close() {
    try {
        if (socket_.is_open()) {
            socket_.close();
        }
        state_ = ConnectionState::CLOSED;
        co_return std::expected<void, TAPSError>{std::in_place};
    } catch (const std::exception& e) {
        state_ = ConnectionState::ERROR;
        co_return std::unexpected(TAPSError(ErrorType::INTERNAL_ERROR, e.what()));
    }
}


asio::awaitable<Result<void>> ActiveUDPConnection::abort() {
    // For UDP, abort is the same as close (no graceful shutdown needed)
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