
#include "taps/taps_api.h"
#include "taps/message_framer.h"
#include "buffer/block_chain.h"
#include "buffer/block_pool.h"
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>
#include <asio/error.hpp>
#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <memory>

namespace taps {

// ============================================================================
// TCP Connection Implementation
// ============================================================================

    TCPConnection::TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint)
        : socket_(ctx), block_pool_(std::make_unique<BlockPool>()),
          receive_chain_(std::make_unique<BlockChain>()){
            remote_endpoint_ = endpoint;
    }

    // Constructor for accepted connections
    TCPConnection::TCPConnection(asio::ip::tcp::socket socket)
        : socket_(std::move(socket)), block_pool_(std::make_unique<BlockPool>()),
          receive_chain_(std::make_unique<BlockChain>()) {
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

    // Out-of-line so ~unique_ptr<BlockPool> is instantiated where BlockPool is complete.
    TCPConnection::~TCPConnection() = default;

    asio::awaitable<Result<void>> TCPConnection::send(const Message& message) {
        if (state_ != ConnectionState::ESTABLISHED) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, 
                                              "Connection not established"));
        }
        
        try {
            if (framer_) {
                // Gather-write: framing header (stack) + untouched payload, one
                // async_write (writev under the hood). No payload copy.
                std::array<std::byte, 64> hdr;
                assert(framer_->max_header_size() <= hdr.size());
                const std::size_t hn = framer_->write_header(message, hdr);
                const auto body = message.as_span();
                const std::array<asio::const_buffer, 2> iov{
                    asio::buffer(hdr.data(), hn),
                    asio::buffer(body.data(), body.size())};
                co_await asio::async_write(socket_, iov, asio::use_awaitable);
            } else if (const BlockChain* chain = message.block_chain()) {
                // Chain-backed Message (e.g. echoing one straight back): gather-write
                // its blocks, no copy.
                std::vector<asio::const_buffer> iov;
                iov.reserve(chain->block_count());
                for (const BlockRef& b : *chain)
                    iov.push_back(asio::buffer(b.data(), b.size()));
                co_await asio::async_write(socket_, iov, asio::use_awaitable);
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
        // RFC 9623 Section 6: the framer parses records out of a receive cursor
        // over the accumulated-but-unparsed bytes (receive_chain_). Each Emit is
        // delivered as a refcounted slice of the chain — no payload copy. Leftover
        // bytes of the next record stay in receive_chain_ for the following call.
        for (;;) {
            ParseResult pr = framer_->parse(ReceiveCursor(*receive_chain_), receive_eof_);

            if (pr.action == ParseResult::Action::Emit) {
                if (pr.discard_before > 0)
                    receive_chain_->consume_front(pr.discard_before);
                auto slice = std::make_shared<BlockChain>(receive_chain_->first(pr.deliver));
                receive_chain_->consume_front(pr.deliver);
                co_return Message(std::move(slice), MessageContext{}, pr.end_of_message);
            }

            // ParseResult::Action::NeedMore
            if (receive_eof_) {
                state_ = ConnectionState::CLOSED;
                co_return Message(std::make_shared<BlockChain>(), MessageContext{},
                                  /*end_of_message=*/true);
            }

            BlockRef block = block_pool_->acquire();
            asio::error_code ec;
            std::size_t n = co_await socket_.async_read_some(
                asio::buffer(block.writable_data(), block.capacity_after_begin()),
                asio::redirect_error(asio::use_awaitable, ec));

            if (ec == asio::error::eof) {
                receive_eof_ = true;
                continue;
            }
            if (ec) {
                state_ = ConnectionState::ERROR;
                co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
            }
            if (n > 0) {
                block.set_range(0, n);
                receive_chain_->append(std::move(block));
            }
        }
    }
    
    asio::awaitable<Result<Message>> TCPConnection::receive_without_framing() {
        // Mode D — RFC 9622 Section 9.3.2.2 (ReceivedPartial). With no Framer the
        // whole connection is one Message of indeterminate length: deliver each
        // chunk as it arrives in a pooled block, with is_end_of_message() bound to
        // the peer's half-close. No accumulation; memory stays bounded for any
        // transfer size. Blocks recycle through block_pool_'s free list, so the
        // steady state does no allocation and no zero-fill.
        BlockRef block = block_pool_->acquire();

        asio::error_code ec;
        std::size_t n = co_await socket_.async_read_some(
            asio::buffer(block.writable_data(), block.capacity_after_begin()),
            asio::redirect_error(asio::use_awaitable, ec));

        if (ec == asio::error::eof) {
            // Graceful close: final fragment, empty, endOfMessage = true.
            state_ = ConnectionState::CLOSED;
            co_return Message(std::make_shared<BlockChain>(), MessageContext{},
                              /*end_of_message=*/true);
        }
        if (ec) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
        }

        auto chain = std::make_shared<BlockChain>();
        if (n > 0) {
            block.set_range(0, n);
            chain->append(std::move(block));
        }
        co_return Message(std::move(chain), MessageContext{}, /*end_of_message=*/false);
    }




} // namespace taps