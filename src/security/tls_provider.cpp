#include "security/tls_provider.h"
#include "security/tls_stream.h"

#include "taps/taps_api.h"   // SecurityParameters, TLSVersion

#include <openssl/ssl.h>

#include <stdexcept>
#include <string>

namespace taps {

namespace {

int openssl_version(TLSVersion v) {
    switch (v) {
        case TLSVersion::TLS_1_2: return TLS1_2_VERSION;
        case TLSVersion::TLS_1_3: return TLS1_3_VERSION;
    }
    return TLS1_2_VERSION;
}

std::string join(const std::vector<std::string>& parts, char sep) {
    std::string out;
    for (const auto& p : parts) {
        if (!out.empty()) out += sep;
        out += p;
    }
    return out;
}

}  // namespace

TlsProvider::TlsProvider(const SecurityParameters& params)
    : context_(asio::ssl::context::tls_client) {
    ::SSL_CTX* ctx = context_.native_handle();

    ::SSL_CTX_set_min_proto_version(ctx, openssl_version(params.min_tls_version()));
    ::SSL_CTX_set_max_proto_version(ctx, openssl_version(params.max_tls_version()));

    context_.set_verify_mode(asio::ssl::verify_peer);

    if (params.trust_anchors().empty()) {
        throw std::runtime_error("SecurityParameters: no trust anchor set "
                                 "(add_trust_anchor is required with verify_peer)");
    }
    for (const std::string& path : params.trust_anchors()) {
        asio::error_code ec;
        context_.load_verify_file(path, ec);
        if (ec) {
            throw std::runtime_error("SecurityParameters: cannot load trust anchor '" +
                                     path + "': " + ec.message());
        }
    }

    if (!params.ciphersuites().empty()) {
        const std::string list = join(params.ciphersuites(), ':');
        if (::SSL_CTX_set_ciphersuites(ctx, list.c_str()) != 1) {
            throw std::runtime_error("SecurityParameters: unknown TLS 1.3 cipher suite in '" +
                                     list + "'");
        }
    }
    if (!params.supported_groups().empty()) {
        const std::string list = join(params.supported_groups(), ':');
        if (::SSL_CTX_set1_groups_list(ctx, list.c_str()) != 1) {
            throw std::runtime_error("SecurityParameters: unknown supported group in '" +
                                     list + "'");
        }
    }

    if (!params.alpn_protocols().empty()) {
        std::string wire;
        for (const std::string& p : params.alpn_protocols()) {
            if (p.empty() || p.size() > 255)
                throw std::runtime_error("SecurityParameters: invalid ALPN id '" + p + "'");
            wire.push_back(static_cast<char>(p.size()));
            wire += p;
        }
        // SSL_CTX_set_alpn_protos returns 0 on success.
        if (::SSL_CTX_set_alpn_protos(
                ctx, reinterpret_cast<const unsigned char*>(wire.data()),
                static_cast<unsigned int>(wire.size())) != 0) {
            throw std::runtime_error("SecurityParameters: failed to set ALPN list");
        }
        required_alpn_ = params.alpn_protocols();
    }
}

asio::awaitable<Result<std::unique_ptr<ByteStream>>>
TlsProvider::secure(asio::ip::tcp::socket& socket, std::string server_name) {
    auto stream = std::make_unique<TlsStream>(socket, context_);

    auto hr = co_await stream->handshake(std::move(server_name));
    if (!hr)
        co_return std::unexpected(hr.error());

    if (!required_alpn_.empty()) {
        const std::string negotiated = stream->negotiated_alpn();
        bool ok = false;
        for (const std::string& a : required_alpn_) {
            if (a == negotiated) { ok = true; break; }
        }
        if (!ok) {
            co_return std::unexpected(TAPSError{
                ErrorType::CONNECTION_FAILED,
                "ALPN mismatch: server selected '" + negotiated + "'"});
        }
    }

    co_return std::unique_ptr<ByteStream>(std::move(stream));
}

}  // namespace taps
