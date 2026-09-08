#pragma once

#include "transport/byte_stream.h"

#include <asio/error.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

namespace taps {

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
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
        co_return n;
    }

    asio::awaitable<Result<std::size_t>> write(
        std::span<const asio::const_buffer> buffers) override {
        asio::error_code ec;
        const std::size_t n = co_await asio::async_write(
            socket_, buffers, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
            co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
        co_return n;
    }

    asio::awaitable<Result<void>> shutdown() override {
        asio::error_code ec;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec)
            co_return std::unexpected(TAPSError{ErrorType::INTERNAL_ERROR, ec.message()});
        co_return std::expected<void, TAPSError>{std::in_place};
    }

private:
    asio::ip::tcp::socket& socket_;
};

}  // namespace taps
