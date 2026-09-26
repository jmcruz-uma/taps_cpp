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

// A ByteStream over a connected TCP socket, held by reference: the owning
// TCPConnection keeps it alive (stream_ is declared after socket_, so it is
// destroyed first).
class PlainStream final : public AsioStream<asio::ip::tcp::socket&> {
public:
    explicit PlainStream(asio::ip::tcp::socket& socket) noexcept
        : AsioStream<asio::ip::tcp::socket&>(socket) {}

    asio::awaitable<Result<void>> shutdown() override {
        asio::error_code ec;
        stream_.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        if (ec)
            co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
        co_return co_await drain_until_eof(stream_);
    }
};

}  // namespace taps
