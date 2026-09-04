
#include "taps/taps_api.h"
#include "taps/message_framer.h"
#include "buffer/block.h"
#include "buffer/block_chain.h"
#include "buffer/block_pool.h"
#include "buffer/heap_block_pool.h"
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

    TCPConnection::TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint,
                                 std::shared_ptr<BlockPoolFactory> pool_factory)
        : socket_(ctx),
          block_pool_(pool_factory ? pool_factory->make() : std::make_unique<HeapBlockPool>()),
          receive_chain_(std::make_unique<BlockChain>()),
          current_block_(std::make_unique<BlockRef>()){
            remote_endpoint_ = endpoint;
    }

    // Constructor for accepted connections
    TCPConnection::TCPConnection(asio::ip::tcp::socket socket,
                                 std::shared_ptr<BlockPoolFactory> pool_factory)
        : socket_(std::move(socket)),
          block_pool_(pool_factory ? pool_factory->make() : std::make_unique<HeapBlockPool>()),
          receive_chain_(std::make_unique<BlockChain>()),
          current_block_(std::make_unique<BlockRef>()) {
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
                const auto body = message.as_bytes();
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
            } else {
                // vector / span variant: one contiguous buffer.
                const auto body = message.as_bytes();
                co_await asio::async_write(socket_,
                    asio::buffer(body.data(), body.size()), asio::use_awaitable);
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

  


    
    // See the declaration in taps_api.h for the reuse policy. current_block_ is
    // kept positioned at an empty window [next_write, next_write) between calls;
    // each delivered chunk is a separate BlockRef sharing the same DataBlock, so
    // several deliveries can live off one pooled block without copying.
    asio::awaitable<Result<BlockRef>> TCPConnection::read_one_chunk() {
        const std::size_t reuse_threshold = block_pool_->block_size() / 4;

        if (!*current_block_ || current_block_->capacity_after_begin() < reuse_threshold) {
            *current_block_ = block_pool_->acquire();
            if (!*current_block_) {
                co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED,
                                                    "receive block pool exhausted"});
            }
        }

        asio::error_code ec;
        const std::size_t n = co_await socket_.async_read_some(
            asio::buffer(current_block_->writable_data(), current_block_->capacity_after_begin()),
            asio::redirect_error(asio::use_awaitable, ec));

        if (ec == asio::error::eof) {
            receive_eof_ = true;
            co_return BlockRef{};   // no bytes this round; caller checks receive_eof_
        }
        if (ec) {
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
        }

        const std::size_t begin = current_block_->begin_offset();
        BlockRef delivered(current_block_->block(), begin, begin + n);  // shares the DataBlock
        current_block_->set_range(begin + n, begin + n);                // reposition, still empty

        if (current_block_->capacity_after_begin() < reuse_threshold)
            current_block_->reset();   // stop reusing; `delivered` keeps the block alive as needed

        co_return delivered;
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

                // The record is a refcounted slice of the chain — no payload copy.
                auto slice = std::make_shared<BlockChain>(receive_chain_->first(pr.deliver));
                receive_chain_->consume_front(pr.deliver);
                Message m(std::move(slice), MessageContext{}, pr.end_of_message);
                if (pr.gather)
                    (void)m.as_bytes();   // gather now, here, not on first app access
                co_return m;
            }

            // ParseResult::Action::NeedMore
            if (receive_eof_) {
                state_ = ConnectionState::CLOSED;
                co_return Message(std::make_shared<BlockChain>(), MessageContext{},
                                  /*end_of_message=*/true);
            }

            auto chunk = co_await read_one_chunk();
            if (!chunk) {
                state_ = ConnectionState::ERROR;
                co_return std::unexpected(chunk.error());
            }
            if (*chunk)
                receive_chain_->append(std::move(*chunk));
            // Otherwise read_one_chunk() hit EOF (receive_eof_ is now set); loop
            // back so parse() is asked again with at_eof=true.
        }
    }

    asio::awaitable<Result<Message>> TCPConnection::receive_without_framing() {
        // Mode D — RFC 9622 Section 9.3.2.2 (ReceivedPartial). With no Framer the
        // whole connection is one Message of indeterminate length: deliver each
        // chunk as it arrives, with is_end_of_message() bound to the peer's
        // half-close. No accumulation; memory stays bounded for any transfer size.
        auto chunk = co_await read_one_chunk();
        if (!chunk) {
            state_ = ConnectionState::ERROR;
            co_return std::unexpected(chunk.error());
        }
        if (!*chunk) {
            // Graceful close: final fragment, empty, endOfMessage = true.
            state_ = ConnectionState::CLOSED;
            co_return Message(std::make_shared<BlockChain>(), MessageContext{},
                              /*end_of_message=*/true);
        }

        auto chain = std::make_shared<BlockChain>();
        chain->append(std::move(*chunk));
        co_return Message(std::move(chain), MessageContext{}, /*end_of_message=*/false);
    }




} // namespace taps