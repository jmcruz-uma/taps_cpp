#pragma once

#include "security/security_provider.h"

#include <asio/ssl.hpp>

#include <string>
#include <vector>

namespace taps {

class SecurityParameters;

// SecurityProvider backed by OpenSSL / asio::ssl. Builds one asio::ssl::context
// from the SecurityParameters (trust anchors, forced cipher suite / group, ALPN,
// minimum protocol version) and reuses it for every connection of the owning
// Preconnection. The constructor throws std::runtime_error on a bad parameter
// (missing CA file, unknown cipher, ...).
class TlsProvider : public SecurityProvider {
public:
    explicit TlsProvider(const SecurityParameters& params);

    asio::awaitable<Result<std::unique_ptr<ByteStream>>>
        secure(asio::ip::tcp::socket& socket, std::string server_name) override;

private:
    asio::ssl::context context_;
    std::vector<std::string> required_alpn_;  // empty = accept any / none
};

}  // namespace taps
