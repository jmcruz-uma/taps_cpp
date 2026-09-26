
#include "taps/taps_api.h"
#include "taps/message_framer.h"
#include "buffer/block.h"
#include "buffer/block_chain.h"
#include "buffer/message_block_pool.h"
#include "transport/plain_stream.h"
#include "transport/const_buffer_sequence.h"
#include "transport/io_error.h"
#include "security/security_provider.h"
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
#include <span>
#include <string>
#include <vector>

namespace taps {

// ============================================================================
// TCP Connection Implementation
// ============================================================================

    TCPConnection::TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint,
                                 const MessageMemoryConfig& memory)
        : socket_(ctx),
          stream_(std::make_unique<PlainStream>(socket_)),
          block_pool_(std::make_unique<MessageBlockPool>(memory)),
          receive_chain_(std::make_unique<BlockChain>()),
          current_block_(std::make_unique<BlockRef>()){
            remote_endpoint_ = endpoint;
    }

    // Constructor for accepted connections
    TCPConnection::TCPConnection(asio::ip::tcp::socket socket,
                                 const MessageMemoryConfig& memory)
        : socket_(std::move(socket)),
          stream_(std::make_unique<PlainStream>(socket_)),
          block_pool_(std::make_unique<MessageBlockPool>(memory)),
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

    // Out-of-line so ~unique_ptr<MessageBlockPool> is instantiated where it is complete.
    TCPConnection::~TCPConnection() = default;

    // The only coroutine of a send: the stream's write is the asio operation itself.
    asio::awaitable<Result<void>> TCPConnection::send(const Message& message) {
        if (state_ != ConnectionState::ESTABLISHED) {
            co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INVALID_STATE,
                                                "Connection not established"));
        }

        // Framing header (on this frame) + the payload as it is: contiguous, or the
        // blocks of a received Message. Nothing is copied.
        std::array<std::byte, 64> hdr;
        std::size_t hn = 0;
        if (framer_) {
            assert(framer_->max_header_size() <= hdr.size());
            hn = framer_->write_header(message, hdr);
        }
        const std::span<const std::byte> header(hdr.data(), hn);
        const BlockChain* chain = message.block_chain();
        const ConstBufferSequence buffers = chain ? ConstBufferSequence(header, *chain)
                                                  : ConstBufferSequence(header, message.as_bytes());

        auto [ec, n] = co_await stream_->write(buffers);
        if (ec) {
            if (ec == asio::error::operation_aborted && !aborted_)
                co_return std::unexpected(TAPSError(ErrorEvent::SEND_ERROR, ErrorReason::INVALID_STATE,
                                                    "Connection closed locally"));
            state_ = ConnectionState::CLOSED;
            co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
        }
        co_return std::expected<void, TAPSError>{std::in_place};
    }

    // Not a coroutine: returns the awaitable of the mode coroutine, which is then the
    // only coroutine frame of ours in a receive. The mode is chosen when receive() is
    // called; the state is checked when the result is awaited.
    asio::awaitable<Result<Message>> TCPConnection::receive() {
        return framer_ ? receive_framed() : receive_unframed();
    }

    std::optional<TAPSError> TCPConnection::receive_refused() const {
        if (can_receive())
            return std::nullopt;
        return TAPSError(ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE,
                         receive_ended_ ? "the stream has ended: no more Messages" : "Connection not established");
    }
    
    asio::awaitable<Result<void>> TCPConnection::close() {
        if (state_ == ConnectionState::CLOSED || state_ == ConnectionState::CLOSING) {
            co_return std::expected<void, TAPSError>{std::in_place};
        }
        
        state_ = ConnectionState::CLOSING;

        // A pending receive() completes with RECEIVE_ERROR / INVALID_STATE: after
        // Close the application must not rely on receiving (RFC 9622 Section 10).
        // Then end this side and wait for the peer's end (RFC 9623 Section 10.1).
        asio::error_code cancel_ec;
        socket_.cancel(cancel_ec);
        auto sd = co_await stream_->shutdown();
        asio::error_code ec;
        socket_.close(ec);
        state_ = ConnectionState::CLOSED;
        if (!sd)
            co_return std::unexpected(sd.error());
        if (ec)
            co_return std::unexpected(TAPSError{ErrorEvent::CONNECTION_ERROR, ErrorReason::INTERNAL_ERROR,
                                                ec.message()});
        co_return std::expected<void, TAPSError>{std::in_place};
    }
    
    // RFC 9623 Section 10.1: the connection is reset (RST), not finished. Pending
    // operations complete with CONNECTION_ERROR / LOCAL_ABORT.
    asio::awaitable<Result<void>> TCPConnection::abort(){
        aborted_ = true;
        asio::error_code ec;
        if (socket_.is_open())
            socket_.set_option(asio::socket_base::linger(true, 0), ec);
        socket_.close(ec);
        state_ = ConnectionState::CLOSED;
        if (ec)
            co_return std::unexpected(TAPSError{ErrorEvent::CONNECTION_ERROR, ErrorReason::INTERNAL_ERROR,
                                                ec.message()});
        co_return std::expected<void, TAPSError>{std::in_place};
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
      
    
    asio::awaitable<Result<void>> TCPConnection::apply_security(
        SecurityProvider& provider, std::string server_name) {
        auto secured = co_await provider.secure(socket_, std::move(server_name));
        if (!secured) {
            state_ = ConnectionState::CLOSED;
            co_return std::unexpected(secured.error());
        }
        stream_ = std::move(*secured);   // the plain PlainStream is dropped here
        co_return std::expected<void, TAPSError>{std::in_place};
    }

    // Forwards to the current I/O stream: a PlainStream reports no security, a
    // TlsStream reports the negotiated parameters. Diagnostic only.
    std::optional<SecurityInfo> TCPConnection::security_info() {
        return stream_->security_info();
    }

    // Method to establish connection (called by Preconnection)
    asio::awaitable<Result<void>> TCPConnection::connect() {
        if (state_ != ConnectionState::ESTABLISHING) {
            co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INVALID_STATE,
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
            state_ = ConnectionState::CLOSED;
            co_return std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR,
                                                ErrorReason::ESTABLISHMENT_FAILED, e.code().message()});
        }
    }

  


    
    // Block policy (see the declaration in taps_api.h): current_block_ is kept
    // positioned at an empty window [next_write, next_write) between reads; each
    // delivered chunk is a separate BlockRef sharing the same DataBlock, so several
    // deliveries can live off one block without copying. Not a coroutine.
    Result<asio::awaitable<IoResult>> TCPConnection::start_read() {
        const std::size_t reuse_threshold = block_pool_->block_size() / 4;
        if (!*current_block_ || current_block_->capacity_after_begin() < reuse_threshold) {
            *current_block_ = block_pool_->acquire();
            if (!*current_block_) {
                return std::unexpected(TAPSError{ErrorEvent::RECEIVE_ERROR, ErrorReason::RESOURCE_EXHAUSTED,
                                                 "receive block pool exhausted"});
            }
        }
        return stream_->read_some(
            asio::buffer(current_block_->writable_data(), current_block_->capacity_after_begin()));
    }

    Result<BlockRef> TCPConnection::finish_read(const std::error_code& ec, std::size_t n) {
        if (ec == asio::error::eof) {
            receive_eof_ = true;
            return BlockRef{};      // the peer ended its side: no bytes this round
        }
        if (ec) {
            TAPSError error = read_failure(ec);
            if (error.event() == ErrorEvent::RECEIVE_ERROR)
                receive_eof_ = true;   // the stream ended, though not cleanly
            return std::unexpected(std::move(error));
        }

        const std::size_t reuse_threshold = block_pool_->block_size() / 4;
        const std::size_t begin = current_block_->begin_offset();
        BlockRef delivered(current_block_->block(), begin, begin + n);  // shares the DataBlock
        current_block_->set_range(begin + n, begin + n);                // reposition, still empty
        if (current_block_->capacity_after_begin() < reuse_threshold)
            current_block_->reset();   // stop reusing; `delivered` keeps the block alive as needed
        return delivered;
    }

    asio::awaitable<Result<Message>> TCPConnection::receive_framed() {
        if (auto refused = receive_refused())
            co_return std::unexpected(std::move(*refused));
        // RFC 9623 Section 6: the framer parses records out of a receive cursor
        // over the accumulated-but-unparsed bytes (receive_chain_). Each Emit is
        // delivered as a refcounted slice of the chain — no payload copy. Leftover
        // bytes of the next record stay in receive_chain_ for the following call.
        for (;;) {
            ParseResult pr = framer_->parse(ReceiveCursor(*receive_chain_), receive_eof_);

            if (pr.action == ParseResult::Action::Emit) {
                const std::size_t consumed = pr.discard_before + pr.deliver;
                if (consumed == 0 || consumed > receive_chain_->size()) {
                    co_return std::unexpected(receive_failure(TAPSError{
                        ErrorEvent::RECEIVE_ERROR, ErrorReason::DEFRAMING_FAILED,
                        consumed == 0 ? "Message Framer emitted a record that consumes no data"
                                      : "Message Framer emitted a record beyond the received data"}));
                }
                if (pr.discard_before > 0)
                    receive_chain_->consume_front(pr.discard_before);

                // The record is a refcounted slice of the chain — no payload copy.
                auto slice = make_chain(block_pool_->resource(), receive_chain_->first(pr.deliver));
                receive_chain_->consume_front(pr.deliver);
                message_open_ = !pr.end_of_message;
                Message m(std::move(slice), MessageContext{}, pr.end_of_message);
                if (pr.gather)
                    (void)m.as_bytes();   // gather now, here, not on first app access
                co_return m;
            }

            // ParseResult::Action::NeedMore
            if (receive_eof_) {
                // RFC 9623 Section 5.2 / RFC 9622 Section 9.3.2.3: a stream that ends
                // inside a Message, or with bytes the framer cannot parse, is a
                // ReceiveError, not a clean end.
                const std::size_t unparsed = receive_chain_->size();
                if (message_open_ || unparsed > 0) {
                    const std::string what = message_open_
                        ? "stream ended before the end of the Message"
                        : "stream ended with " + std::to_string(unparsed) +
                          " bytes the Message Framer could not parse";
                    receive_chain_->consume_front(unparsed);
                    message_open_ = false;
                    co_return std::unexpected(receive_failure(TAPSError{
                        ErrorEvent::RECEIVE_ERROR, ErrorReason::DEFRAMING_FAILED, what}));
                }
                receive_ended_ = true;
                co_return Message(make_chain(block_pool_->resource()), MessageContext{},
                                  /*end_of_message=*/true);
            }

            auto read = start_read();
            if (!read)
                co_return std::unexpected(receive_failure(read.error()));
            auto [ec, n] = co_await std::move(*read);
            auto chunk = finish_read(ec, n);
            if (!chunk)
                co_return std::unexpected(receive_failure(chunk.error()));
            if (*chunk)
                receive_chain_->append(std::move(*chunk));
            // Otherwise the read hit EOF (receive_eof_ is now set); loop back so
            // parse() is asked again with at_eof=true.
        }
    }

    asio::awaitable<Result<Message>> TCPConnection::receive_unframed() {
        if (auto refused = receive_refused())
            co_return std::unexpected(std::move(*refused));
        // Mode D — RFC 9622 Section 9.3.2.2 (ReceivedPartial). With no Framer the
        // whole connection is one Message of indeterminate length: deliver each
        // chunk as it arrives, with is_end_of_message() bound to the peer's
        // half-close. No accumulation; memory stays bounded for any transfer size.
        auto read = start_read();
        if (!read)
            co_return std::unexpected(receive_failure(read.error()));
        auto [ec, n] = co_await std::move(*read);
        auto chunk = finish_read(ec, n);
        if (!chunk)
            co_return std::unexpected(receive_failure(chunk.error()));
        if (!*chunk) {
            // The peer ended its side: final fragment, empty, endOfMessage = true.
            receive_ended_ = true;
            co_return Message(make_chain(block_pool_->resource()), MessageContext{},
                              /*end_of_message=*/true);
        }

        auto chain = make_chain(block_pool_->resource());
        chain->append(std::move(*chunk));
        co_return Message(std::move(chain), MessageContext{}, /*end_of_message=*/false);
    }

    // A pending read cancelled by close() is reported as INVALID_STATE (by abort(),
    // it stays LOCAL_ABORT). A CONNECTION_ERROR ends the Connection. A RECEIVE_ERROR
    // leaves it ESTABLISHED; once the peer's stream has ended, it is the last
    // receive result, and the Connection can still send (RFC 9623 Section 10.1).
    TAPSError TCPConnection::receive_failure(TAPSError error) {
        if (error.reason() == ErrorReason::LOCAL_ABORT && !aborted_)
            error = TAPSError{ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE,
                              "Connection closed locally"};
        if (error.event() == ErrorEvent::CONNECTION_ERROR)
            state_ = ConnectionState::CLOSED;
        else if (receive_eof_)
            receive_ended_ = true;
        return error;
    }

    bool TCPConnection::can_receive() const noexcept {
        return state_ == ConnectionState::ESTABLISHED && !receive_ended_;
    }




} // namespace taps