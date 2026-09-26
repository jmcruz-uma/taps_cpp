#pragma once

#include "transport/byte_stream.h"

#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>

#include <optional>
#include <string>

namespace taps {

// A ByteStream backed by an OpenSSL record layer over a connected TCP socket. The
// socket is held by reference and stays owned by the TCPConnection (connect() /
// abort() / endpoint queries keep using it directly). The asio::ssl::context is
// owned by the TlsProvider that created this stream and must outlive it.
class TlsStream final : public AsioStream<asio::ssl::stream<asio::ip::tcp::socket&>> {
public:
    TlsStream(asio::ip::tcp::socket& socket, asio::ssl::context& context)
        : AsioStream<asio::ssl::stream<asio::ip::tcp::socket&>>(socket, context) {}

    // TLS handshake, called once before any read/write.
    //  - client: sets SNI and host-name verification to `server_name`, negotiates.
    //  - server: negotiates using the context's certificate; no name to verify.
    asio::awaitable<Result<void>> handshake_client(std::string server_name);
    asio::awaitable<Result<void>> handshake_server();

    // The ALPN protocol the handshake selected, or "" if none was negotiated.
    // Not const: asio::ssl::stream::native_handle() is non-const.
    std::string negotiated_alpn();

    // The negotiated TLS version / cipher / group / ALPN plus the linked OpenSSL
    // version. Non-const for the same reason as negotiated_alpn(). Always engaged
    // once handshake_*() has returned.
    std::optional<SecurityInfo> security_info() override;

    asio::awaitable<Result<void>> shutdown() override;
};

}  // namespace taps
