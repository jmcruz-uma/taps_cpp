#pragma once

#include "transport/byte_stream.h"

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>

#include <memory>
#include <string>

namespace taps {

// Turns an established transport into a secured one. A Preconnection builds one of
// these (once) from its SecurityParameters when security is requested, and the
// establishment phase applies it to the winning TCPConnection. TlsProvider is the
// only implementation today; a future QuicSecurityProvider / DtlsProvider slots in
// here without touching TCPConnection or the establishment seam.
class SecurityProvider {
public:
    virtual ~SecurityProvider() = default;

    // Run the security handshake over `socket` and, on success, return a ByteStream
    // that speaks the secured protocol. `server_name` is the identity the peer
    // certificate is validated against (and is sent as SNI).
    virtual asio::awaitable<Result<std::unique_ptr<ByteStream>>>
        secure(asio::ip::tcp::socket& socket, std::string server_name) = 0;
};

}  // namespace taps
