#pragma once

#include "transport/byte_stream.h"
#include "transport/io_error.h"

#include <asio/error.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <array>
#include <cstddef>

namespace taps {

// Reads and discards until the peer ends its side of the connection (EOF). Used
// after this side has ended, so that the socket is released with nothing unread:
// the kernel resets, instead of finishing, a connection closed with unread data.
inline asio::awaitable<Result<void>> drain_until_eof(asio::ip::tcp::socket& socket) {
    std::array<std::byte, 4096> sink;
    for (;;) {
        asio::error_code ec;
        co_await socket.async_read_some(asio::buffer(sink),
                                        asio::redirect_error(asio::use_awaitable, ec));
        if (ec == asio::error::eof)
            co_return std::expected<void, TAPSError>{std::in_place};
        if (ec)
            co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
    }
}

// A ByteStream that forwards directly to a connected TCP socket. Holds the socket
// by reference: the owning TCPConnection keeps it alive (stream_ is declared after
// socket_, so it is destroyed first). This is the behaviour of the connection
// before any security is applied.
class PlainStream : public ByteStream {
public:
    explicit PlainStream(asio::ip::tcp::socket& socket) noexcept : socket_(socket) {}

    asio::awaitable<Result<std::size_t>> read_some(asio::mutable_buffer buffer) override {
        asio::error_code ec;
        const std::size_t n = co_await socket_.async_read_some(
            buffer, asio::redirect_error(asio::use_awaitable, ec));
        if (ec == asio::error::eof)
            co_return std::size_t{0};
        if (ec)
            co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
        co_return n;
    }

    asio::awaitable<Result<std::size_t>> write(
        std::span<const asio::const_buffer> buffers) override {
        asio::error_code ec;
        const std::size_t n = co_await asio::async_write(
            socket_, buffers, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
            co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
        co_return n;
    }

    asio::awaitable<Result<void>> shutdown() override {
        asio::error_code ec;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        if (ec)
            co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
        co_return co_await drain_until_eof(socket_);
    }

private:
    asio::ip::tcp::socket& socket_;
};

}  // namespace taps
