#pragma once

#include "transport/byte_stream.h"

#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>

#include <string>

namespace taps {

// A ByteStream backed by an OpenSSL record layer over a connected TCP socket. The
// socket is held by reference and stays owned by the TCPConnection (connect() /
// abort() / endpoint queries keep using it directly). The asio::ssl::context is
// owned by the TlsProvider that created this stream and must outlive it.
class TlsStream : public ByteStream {
public:
    TlsStream(asio::ip::tcp::socket& socket, asio::ssl::context& context)
        : ssl_(socket, context) {}

    // Client-side TLS handshake: sets SNI and host-name verification to
    // `server_name`, then negotiates. Called once, before any read/write.
    asio::awaitable<Result<void>> handshake(std::string server_name);

    // The ALPN protocol the handshake selected, or "" if none was negotiated.
    // Not const: asio::ssl::stream::native_handle() is non-const.
    std::string negotiated_alpn();

    asio::awaitable<Result<std::size_t>> read_some(asio::mutable_buffer buffer) override;
    asio::awaitable<Result<std::size_t>> write(
        std::span<const asio::const_buffer> buffers) override;
    asio::awaitable<Result<void>> shutdown() override;

private:
    asio::ssl::stream<asio::ip::tcp::socket&> ssl_;
};

}  // namespace taps
