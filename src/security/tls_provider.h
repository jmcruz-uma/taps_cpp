#pragma once

#include "security/security_provider.h"

#include <asio/ssl.hpp>

#include <memory>
#include <string>
#include <vector>

namespace taps {

class SecurityParameters;

// SecurityProvider backed by OpenSSL / asio::ssl. Holds one asio::ssl::context
// built from the SecurityParameters and reuses it for every connection of the
// owning Preconnection (client) or TCPListener (server). Construction is
// exception-free: create() returns an error (never throws) on a bad parameter
// such as a missing CA / server key, an unknown cipher suite or an unknown group.
class TlsProvider : public SecurityProvider {
public:
    enum class Role { Client, Server };

    static Result<std::unique_ptr<TlsProvider>> create(const SecurityParameters& params,
                                                       Role role);

    asio::awaitable<Result<std::unique_ptr<ByteStream>>>
        secure(asio::ip::tcp::socket& socket, std::string server_name) override;

private:
    TlsProvider(asio::ssl::context context, Role role,
                std::vector<std::string> required_alpn);

    // ALPN select callback for the server side; reads alpn_wire_ via `arg`.
    static int alpn_select_cb(::SSL* ssl, const unsigned char** out, unsigned char* outlen,
                              const unsigned char* in, unsigned int inlen, void* arg);

    asio::ssl::context context_;
    Role role_;
    std::vector<std::string> required_alpn_;  // client: post-handshake check; empty = any
    std::string alpn_wire_;                   // server: length-prefixed preference list
};

}  // namespace taps
