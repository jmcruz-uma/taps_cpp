
#include "taps/taps_api.h"
#include <asio/use_awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <algorithm>

namespace taps {


// ============================================================================
// TCP Listener Implementation
// ============================================================================

TCPListener::TCPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties,
                        SecurityParameters security)
        : io_context_(ctx), acceptor_(ctx){
            local_endpoint_ = std::move(local);
            transport_properties_ = std::move(properties); 
            security_parameters_ = std::move(security);
        }
    
asio::awaitable<Result<void>> TCPListener::listen() {
        if (is_listening_) {
            co_return std::unexpected(TAPSError{ErrorType::INVALID_CONFIGURATION, 
                                              "Already listening"});
        }
        
        try {
            // Resolve local endpoint
            auto endpoints = co_await local_endpoint_.resolve(io_context_);
            if (endpoints.empty()) {
                co_return std::unexpected(TAPSError{ErrorType::RESOLUTION_FAILED, 
                                                  "Failed to resolve local endpoint"});
            }
            
            // Try to bind to resolved endpoints
            bool bound = false;
            for (const auto& endpoint : endpoints) {
                try {
                    acceptor_.open(endpoint.protocol());
                    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
                    acceptor_.bind(endpoint);
                    acceptor_.listen();
                    bound = true;
                    break;
                } catch (const std::system_error&) {
                    // Try next endpoint
                    if (acceptor_.is_open()) {
                        acceptor_.close();
                    }
                }
            }
            
            if (!bound) {
                co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                                  "Failed to bind to any endpoint"});
            }
            
            is_listening_ = true;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              e.code().message()});
        }
    }
    
    asio::awaitable<Result<std::unique_ptr<Connection>>> TCPListener::accept() {
        if (!is_listening_) {
            co_return std::unexpected(TAPSError{ErrorType::INVALID_CONFIGURATION, 
                                              "Not listening"});
        }
        
        try {
            auto socket = co_await acceptor_.async_accept(asio::use_awaitable);
            
            // Create connection from accepted socket
            auto connection = std::make_unique<TCPConnection>(std::move(socket));
            
            co_return std::unique_ptr<Connection>(std::move(connection));
            
        } catch (const std::system_error& e) {
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, 
                                              e.code().message()});
        }
    }
    
    asio::awaitable<Result<void>> TCPListener::stop() {
        if (!is_listening_) {
            co_return std::expected<void, TAPSError>{std::in_place};
        }
        
        try {
            acceptor_.close();
            is_listening_ = false;
            co_return std::expected<void, TAPSError>{std::in_place};
            
        } catch (const std::system_error& e) {
            co_return std::unexpected(TAPSError{ErrorType::INTERNAL_ERROR, 
                                              e.code().message()});
        }
    }
    
    bool TCPListener::is_listening() const noexcept { 
        return is_listening_; 
    }
    
    LocalEndpoint TCPListener::get_local_endpoint() const {
        if (acceptor_.is_open()) {
            try {
                auto endpoint = acceptor_.local_endpoint();
                return LocalEndpoint(endpoint.address().to_string(), endpoint.port());
            } catch (const std::exception&) {
                // Fall through to return configured endpoint
            }
        }
        return local_endpoint_;
    }



// ============================================================================
// Example Framer Implementation
// ============================================================================
inline std::size_t LengthPrefixedFramer::frame_message(const Message& msg,
                                                          std::vector<std::uint8_t>& out_buffer) {
    const auto& data = msg.data();
    out_buffer.clear();
    
    // Reserve space for length + data
    out_buffer.reserve(length_field_size_ + data.size());
    
    // Write length field
    std::uint32_t length = static_cast<std::uint32_t>(data.size());
    
    if (byte_order_ == std::endian::big) {
        // Network byte order (big endian)
        for (int i = length_field_size_ - 1; i >= 0; --i) {
            out_buffer.push_back(static_cast<std::uint8_t>((length >> (i * 8)) & 0xFF));
        }
    } else {
        // Little endian
        for (std::size_t i = 0; i < length_field_size_; ++i) {
            out_buffer.push_back(static_cast<std::uint8_t>((length >> (i * 8)) & 0xFF));
        }
    }
    
    // Append message data
    out_buffer.insert(out_buffer.end(), data.begin(), data.end());
    
    return out_buffer.size();
}

inline bool LengthPrefixedFramer::has_complete_message(std::span<const std::uint8_t> buffer) const {
    if (buffer.size() < length_field_size_) {
        return false;
    }
    
    // Read length field
    std::uint32_t length = 0;
    if (byte_order_ == std::endian::big) {
        for (std::size_t i = 0; i < length_field_size_; ++i) {
            length = (length << 8) | buffer[i];
        }
    } else {
        for (std::size_t i = 0; i < length_field_size_; ++i) {
            length |= (static_cast<std::uint32_t>(buffer[i]) << (i * 8));
        }
    }
    
    return buffer.size() >= (length_field_size_ + length);
}

// Add this to complete the LengthPrefixedFramer implementation
inline std::size_t LengthPrefixedFramer::parse_stream(std::span<const std::uint8_t> buffer,
                                                      std::vector<Message>& out_messages) {
    std::size_t offset = 0;
    
    while (offset + length_field_size_ <= buffer.size()) {
        // Read length field
        std::uint32_t length = 0;
        if (byte_order_ == std::endian::big) {
            for (std::size_t i = 0; i < length_field_size_; ++i) {
                length = (length << 8) | buffer[offset + i];
            }
        } else {
            for (std::size_t i = 0; i < length_field_size_; ++i) {
                length |= (static_cast<std::uint32_t>(buffer[offset + i]) << (i * 8));
            }
        }
        
        // Check if we have the complete message
        if (offset + length_field_size_ + length > buffer.size()) {
            break; // Incomplete message
        }
        
        // Extract message data
        auto data_start = buffer.begin() + offset + length_field_size_;
        auto data_end = data_start + length;
        std::vector<std::uint8_t> data(data_start, data_end);
        
        out_messages.emplace_back(std::move(data));
        offset += length_field_size_ + length;
    }
    
    return offset;
}

inline void LengthPrefixedFramer::reset() {
    expected_message_length_ = 0;
    length_read_ = false;
}



} // namespace taps