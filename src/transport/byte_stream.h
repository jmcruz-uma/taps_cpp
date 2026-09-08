#pragma once

#include "taps/taps_api.h"   // Result, TAPSError, ErrorType

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>

#include <cstddef>
#include <span>

namespace taps {

// The byte transport a TCPConnection performs its I/O through. A PlainStream
// forwards straight to the socket; a TlsStream (added with the security provider)
// runs the same calls through an OpenSSL record layer. TCPConnection holds one of
// these and never names a concrete transport or TLS type — security is a
// transversal concern kept out of the connection class.
class ByteStream {
public:
    virtual ~ByteStream() = default;

    // Read up to buffer.size() bytes. Returns the count read; 0 means the peer
    // half-closed the read side (EOF). A transport error is reported as unexpected.
    virtual asio::awaitable<Result<std::size_t>> read_some(asio::mutable_buffer buffer) = 0;

    // Write every byte of every buffer (asio::async_write semantics). Returns the
    // total number of bytes written.
    virtual asio::awaitable<Result<std::size_t>> write(
        std::span<const asio::const_buffer> buffers) = 0;

    // Graceful shutdown of the write direction: a TCP FIN for a PlainStream, a TLS
    // close_notify for a TlsStream.
    virtual asio::awaitable<Result<void>> shutdown() = 0;
};

}  // namespace taps
