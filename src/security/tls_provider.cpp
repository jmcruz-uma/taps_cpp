#include "security/tls_provider.h"
#include "security/tls_stream.h"

#include "taps/taps_api.h"   // SecurityParameters, TLSVersion

#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <string>
#include <utility>

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

// Length-prefixed wire form of an ALPN id list; returns "" if any id is invalid.
std::string alpn_wire(const std::vector<std::string>& ids) {
    std::string wire;
    for (const std::string& id : ids) {
        if (id.empty() || id.size() > 255)
            return {};
        wire.push_back(static_cast<char>(id.size()));
        wire += id;
    }
    return wire;
}

using ProviderResult = Result<std::unique_ptr<TlsProvider>>;

ProviderResult fail(std::string msg) {
    return std::unexpected(TAPSError{ErrorType::INVALID_CONFIGURATION, std::move(msg)});
}

}  // namespace

TlsProvider::TlsProvider(asio::ssl::context context, Role role,
                         std::vector<std::string> required_alpn)
    : context_(std::move(context)),
      role_(role),
      required_alpn_(std::move(required_alpn)) {}

int TlsProvider::alpn_select_cb(::SSL*, const unsigned char** out, unsigned char* outlen,
                                const unsigned char* in, unsigned int inlen, void* arg) {
    const auto* self = static_cast<const TlsProvider*>(arg);
    const std::string& pref = self->alpn_wire_;
    unsigned char* chosen = nullptr;
    if (::SSL_select_next_proto(&chosen, outlen,
                                reinterpret_cast<const unsigned char*>(pref.data()),
                                static_cast<unsigned int>(pref.size()),
                                in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = chosen;
    return SSL_TLSEXT_ERR_OK;
}

ProviderResult TlsProvider::create(const SecurityParameters& params, Role role) {
    // Own the SSL_CTX explicitly so no asio::ssl::context constructor (which has no
    // error_code overload) is on the path.
    ::SSL_CTX* raw = ::SSL_CTX_new(role == Role::Client ? ::TLS_client_method()
                                                        : ::TLS_server_method());
    if (raw == nullptr)
        return fail("SSL_CTX_new failed");
    asio::ssl::context context(raw);   // adopts ownership
    ::SSL_CTX* ctx = context.native_handle();

    ::SSL_CTX_set_min_proto_version(ctx, openssl_version(params.min_tls_version()));
    ::SSL_CTX_set_max_proto_version(ctx, openssl_version(params.max_tls_version()));

    asio::error_code ec;

    if (role == Role::Client) {
        context.set_verify_mode(asio::ssl::verify_peer, ec);
        if (ec) return fail("set_verify_mode: " + ec.message());
        if (params.trust_anchors().empty())
            return fail("no trust anchor set (add_trust_anchor is required with verify_peer)");
        for (const std::string& path : params.trust_anchors()) {
            context.load_verify_file(path, ec);
            if (ec) return fail("cannot load trust anchor '" + path + "': " + ec.message());
        }
    } else {
        if (params.certificate_chain_file().empty() || params.private_key_file().empty())
            return fail("server TLS needs set_certificate_chain_file and set_private_key_file");
        context.use_certificate_chain_file(params.certificate_chain_file(), ec);
        if (ec) return fail("cannot load certificate chain '" +
                            params.certificate_chain_file() + "': " + ec.message());
        context.use_private_key_file(params.private_key_file(), asio::ssl::context::pem, ec);
        if (ec) return fail("cannot load private key '" +
                            params.private_key_file() + "': " + ec.message());
    }

    if (!params.ciphersuites().empty()) {
        const std::string list = join(params.ciphersuites(), ':');
        if (::SSL_CTX_set_ciphersuites(ctx, list.c_str()) != 1)
            return fail("unknown TLS 1.3 cipher suite in '" + list + "'");
    }
    if (!params.supported_groups().empty()) {
        const std::string list = join(params.supported_groups(), ':');
        if (::SSL_CTX_set1_groups_list(ctx, list.c_str()) != 1)
            return fail("unknown supported group in '" + list + "'");
    }

    std::string wire;
    std::vector<std::string> required_alpn;
    if (!params.alpn_protocols().empty()) {
        wire = alpn_wire(params.alpn_protocols());
        if (wire.empty())
            return fail("invalid ALPN id");
        required_alpn = params.alpn_protocols();
        if (role == Role::Client) {
            // SSL_CTX_set_alpn_protos returns 0 on success.
            if (::SSL_CTX_set_alpn_protos(
                    ctx, reinterpret_cast<const unsigned char*>(wire.data()),
                    static_cast<unsigned int>(wire.size())) != 0) {
                return fail("failed to set ALPN list");
            }
        }
    }

    std::unique_ptr<TlsProvider> provider(
        new TlsProvider(std::move(context), role, std::move(required_alpn)));

    if (role == Role::Server && !wire.empty()) {
        provider->alpn_wire_ = std::move(wire);
        ::SSL_CTX_set_alpn_select_cb(provider->context_.native_handle(),
                                     &TlsProvider::alpn_select_cb, provider.get());
    }

    return provider;
}

asio::awaitable<Result<std::unique_ptr<ByteStream>>>
TlsProvider::secure(asio::ip::tcp::socket& socket, std::string server_name) {
    auto stream = std::make_unique<TlsStream>(socket, context_);

    if (role_ == Role::Client) {
        auto hr = co_await stream->handshake_client(std::move(server_name));
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
    } else {
        auto hr = co_await stream->handshake_server();
        if (!hr)
            co_return std::unexpected(hr.error());
    }

    co_return std::unique_ptr<ByteStream>(std::move(stream));
}

}  // namespace taps
