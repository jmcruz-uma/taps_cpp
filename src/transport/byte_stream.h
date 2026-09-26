#pragma once

#include "taps/taps_api.h"                       // Result, TAPSError, SecurityInfo
#include "transport/const_buffer_sequence.h"

#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <cstddef>
#include <optional>
#include <system_error>
#include <tuple>
#include <utility>

namespace taps {

// Outcome of one read or write: the error (if any) and the bytes transferred.
using IoResult = std::tuple<std::error_code, std::size_t>;

// The byte transport a TCPConnection performs its I/O through: a plain socket, or
// the same socket under a TLS record layer. TCPConnection holds one and never names
// a concrete transport or TLS type.
//
// read_some() and write() are not coroutines: they return the asio operation for
// the caller to co_await, so a read or a write adds no coroutine frame of its own.
class ByteStream {
public:
    virtual ~ByteStream() = default;

    // Reads up to buffer.size() bytes. asio::error::eof means the peer ended its side;
    // any other error is interpreted by read_failure().
    virtual asio::awaitable<IoResult> read_some(asio::mutable_buffer buffer) = 0;

    // Writes every byte of `buffers` (asio::async_write semantics).
    virtual asio::awaitable<IoResult> write(const ConstBufferSequence& buffers) = 0;

    // Graceful end of the connection (RFC 9623 Section 10.1, Close): ends this side
    // (a TCP FIN, or a TLS close_notify) and completes once the peer has ended its
    // side, discarding whatever the peer still sends. Only the send direction is
    // shut down first, so the peer can finish its own sending. A failure is a
    // CONNECTION_ERROR.
    virtual asio::awaitable<Result<void>> shutdown() = 0;

    // The negotiated TLS parameters, for diagnostics only (see SecurityInfo). A
    // plain stream has none.
    virtual std::optional<SecurityInfo> security_info() { return std::nullopt; }
};

// read_some() and write() for any asio stream `S` (a socket, or a TLS stream over it).
template <typename S>
class AsioStream : public ByteStream {
public:
    template <typename... Args>
    explicit AsioStream(Args&&... args) : stream_(std::forward<Args>(args)...) {}

    asio::awaitable<IoResult> read_some(asio::mutable_buffer buffer) final {
        return stream_.async_read_some(buffer, asio::as_tuple(asio::use_awaitable));
    }

    asio::awaitable<IoResult> write(const ConstBufferSequence& buffers) final {
        return asio::async_write(stream_, buffers, asio::as_tuple(asio::use_awaitable));
    }

protected:
    S stream_;
};

// The error a failed read means for the Connection. A TLS stream cut without
// close_notify is a RECEIVE_ERROR (the data may be incomplete, and nothing more will
// arrive); any other failure ends the Connection (CONNECTION_ERROR).
TAPSError read_failure(const std::error_code& ec);

}  // namespace taps
