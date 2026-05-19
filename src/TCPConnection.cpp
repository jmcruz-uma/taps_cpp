
#include "taps/taps_api.h"
#include <asio/use_awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <algorithm>

namespace taps {

// ============================================================================
// TCP Connection Implementation
// ============================================================================

    TCPConnection::TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint)
        : socket_(ctx), receive_buffer_(8192){
            remote_endpoint_ = endpoint;
    }
    
    // Constructor for accepted connections
    TCPConnection::TCPConnection(asio::ip::tcp::socket socket)
        : socket_(std::move(socket)), receive_buffer_(8192) {
        state_ = ConnectionState::ESTABLISHED;
        
        // Cache endpoints
        if (socket_.is_open()) {
            try {
                cached_remote_endpoint_ = socket_.remote_endpoint();
                cached_local_endpoint_ = socket_.local_endpoint();
            } catch (const std::exception&) {
                // Handle gracefully - endpoints will be default constructed
            }
        }
    }
    
    asio::awaitable<Result<void>> TCPConnection::send(const Message& message) {
        if (state_ != ConnectionState::ESTABLISHED) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, 
                                              "Connection not established"));
        }
        
        try {
            if (framer_) {
                send_buffer_.clear();
                framer_->frame_message(message, send_buffer_);
                co_await asio::async_write(socket_, 
                    asio::buffer(send_buffer_), asio::use_awaitable);
            } else if (message.is_owning()) {
                co_await asio::async_write(socket_,
                    asio::buffer(message.data()), asio::use_awaitable);
            } else {
                auto s = message.view();
                co_await asio::async_write(socket_,
                    asio::buffer(s.data(), s.size()), asio::use_awaitable);
            }
            
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, 
                                              e.code().message()));
        }
    }
    
    asio::awaitable<Result<Message>> TCPConnection::receive() {
        if (state_ != ConnectionState::ESTABLISHED) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, 
                                              "Connection not established"));
        }
        
        try {
            if (framer_) {
                co_return co_await receive_with_framing();
            } else {
                co_return co_await receive_without_framing();
            }
            
        } catch (const std::system_error& e) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              e.code().message()});
        }
    }
    
    asio::awaitable<Result<void>> TCPConnection::close() {
        if (state_ == ConnectionState::CLOSED || state_ == ConnectionState::CLOSING) {
            co_return std::expected<void, TAPSError>{std::in_place};
        }
        
        state_ = ConnectionState::CLOSING;
        
        try {
            // Graceful shutdown
            socket_.shutdown(asio::ip::tcp::socket::shutdown_both);
            socket_.close();
            state_ = ConnectionState::CLOSED;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(TAPSError{ErrorType::INTERNAL_ERROR, 
                                              e.code().message()});
        }
    }
    
    asio::awaitable<Result<void>> TCPConnection::abort(){
        try {
            socket_.close();
            state_ = ConnectionState::CLOSED;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(TAPSError{ErrorType::INTERNAL_ERROR, 
                                              e.code().message()});
        }
    }
    
    RemoteEndpoint TCPConnection::get_remote_endpoint() const{
        if (cached_remote_endpoint_) {
            return RemoteEndpoint(cached_remote_endpoint_->address().to_string(), 
                                cached_remote_endpoint_->port());
        }
        return RemoteEndpoint("", 0);
    }
    
    LocalEndpoint TCPConnection::get_local_endpoint() const{
        if (cached_local_endpoint_) {
            return LocalEndpoint(cached_local_endpoint_->address().to_string(), 
                               cached_local_endpoint_->port());
        }
        return LocalEndpoint("", 0);
    }
      
    
    // Method to establish connection (called by Preconnection)
    asio::awaitable<Result<void>> TCPConnection::connect() {
        if (state_ != ConnectionState::ESTABLISHING) {
            co_return std::unexpected(TAPSError{ErrorType::INVALID_CONFIGURATION, 
                                              "Connection not in establishing state"});
        }
        
        try {
            co_await socket_.async_connect(remote_endpoint_, asio::use_awaitable);
            
            // Cache endpoints after successful connection
            cached_remote_endpoint_ = socket_.remote_endpoint();
            cached_local_endpoint_ = socket_.local_endpoint();
            
            state_ = ConnectionState::ESTABLISHED;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              e.code().message()});
        }
    }

  


    
    asio::awaitable<Result<Message>> TCPConnection::receive_with_framing() {
        while (true) {
            // Check if we have a complete message in buffer
            if (!partial_frame_buffer_.empty()) {
                if (framer_->has_complete_message(partial_frame_buffer_)) {
                    std::vector<Message> messages;
                    auto consumed = framer_->parse_stream(partial_frame_buffer_, messages);
                    if (!messages.empty()) {
                        auto message = std::move(messages.front());
                        partial_frame_buffer_.erase(
                            partial_frame_buffer_.begin(),
                            partial_frame_buffer_.begin() + std::min(consumed, partial_frame_buffer_.size())
                        );
                        co_return std::move(message);
                    }
                }
            }
            
            // Need more data
            auto bytes_read = co_await socket_.async_read_some(
                asio::buffer(receive_buffer_), asio::use_awaitable);
            
            if (bytes_read == 0) {
                // Connection closed by peer
                state_ = ConnectionState::CLOSED;
                co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                                  "Connection closed by peer"});
            }
            
            // Append to partial buffer
            partial_frame_buffer_.insert(partial_frame_buffer_.end(),
                                       receive_buffer_.begin(), 
                                       receive_buffer_.begin() + bytes_read);
        }
    }
    
    asio::awaitable<Result<Message>> TCPConnection::receive_without_framing() {
        // Without framing, we just read available data
        auto bytes_read = co_await socket_.async_read_some(
            asio::buffer(receive_buffer_), asio::use_awaitable);
        
        if (bytes_read == 0) {
            state_ = ConnectionState::CLOSED;
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              "Connection closed by peer"});
        }
        
        std::vector<std::uint8_t> data(receive_buffer_.begin(), 
                                     receive_buffer_.begin() + bytes_read);
        co_return Message(std::move(data));
    }




} // namespace taps