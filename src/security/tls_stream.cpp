#include "security/tls_stream.h"
#include "transport/io_error.h"
#include "transport/plain_stream.h"   // drain_until_eof

#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace taps {

asio::awaitable<Result<void>> TlsStream::handshake_client(std::string server_name) {
    if (!server_name.empty()) {
        // SNI: tell the server which name we expect, so it can pick the right cert.
        if (::SSL_set_tlsext_host_name(ssl_.native_handle(), server_name.c_str()) != 1) {
            co_return std::unexpected(
                TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR,
                      "failed to set TLS SNI host name"});
        }
        // Validate the presented certificate against the same name.
        asio::error_code vc_ec;
        ssl_.set_verify_callback(asio::ssl::host_name_verification(server_name), vc_ec);
        if (vc_ec) {
            co_return std::unexpected(
                TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR,
                      "set_verify_callback: " + vc_ec.message()});
        }
    }

    asio::error_code ec;
    co_await ssl_.async_handshake(asio::ssl::stream_base::client,
                                 asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return std::unexpected(
            TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::ESTABLISHMENT_FAILED,
                      "TLS handshake failed: " + ec.message()});
    }
    co_return std::expected<void, TAPSError>{std::in_place};
}

asio::awaitable<Result<void>> TlsStream::handshake_server() {
    asio::error_code ec;
    co_await ssl_.async_handshake(asio::ssl::stream_base::server,
                                 asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return std::unexpected(
            TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::ESTABLISHMENT_FAILED,
                      "TLS handshake failed: " + ec.message()});
    }
    co_return std::expected<void, TAPSError>{std::in_place};
}

std::string TlsStream::negotiated_alpn() {
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    ::SSL_get0_alpn_selected(ssl_.native_handle(), &proto, &len);
    if (proto == nullptr || len == 0)
        return {};
    return std::string(reinterpret_cast<const char*>(proto), len);
}

std::optional<SecurityInfo> TlsStream::security_info() {
    ::SSL* ssl = ssl_.native_handle();

    SecurityInfo info;
    info.openssl_version = ::OpenSSL_version(OPENSSL_VERSION);

    if (const char* v = ::SSL_get_version(ssl))
        info.tls_version = v;

    if (const ::SSL_CIPHER* cipher = ::SSL_get_current_cipher(ssl)) {
        if (const char* name = ::SSL_CIPHER_get_name(cipher))
            info.cipher = name;
    }

    // SSL_get_negotiated_group() yields the TLS group id of the key-exchange
    // group; SSL_group_to_name() turns it into "X25519" etc. (null if unknown).
    if (const char* group = ::SSL_group_to_name(ssl, ::SSL_get_negotiated_group(ssl)))
        info.group = group;

    info.alpn = negotiated_alpn();
    return info;
}

asio::awaitable<Result<std::size_t>> TlsStream::read_some(asio::mutable_buffer buffer) {
    asio::error_code ec;
    const std::size_t n = co_await ssl_.async_read_some(
        buffer, asio::redirect_error(asio::use_awaitable, ec));
    // A clean close_notify surfaces as eof. A peer that closed the TCP connection
    // without one surfaces as stream_truncated: no more data will come, and the data
    // received cannot be known to be complete.
    if (ec == asio::error::eof)
        co_return std::size_t{0};
    if (ec == asio::ssl::error::stream_truncated)
        co_return std::unexpected(TAPSError{ErrorEvent::RECEIVE_ERROR, ErrorReason::PROTOCOL_FAILED,
                                            "TLS stream truncated: peer closed without close_notify"});
    if (ec)
        co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
    co_return n;
}

asio::awaitable<Result<std::size_t>> TlsStream::write(
    std::span<const asio::const_buffer> buffers) {
    asio::error_code ec;
    const std::size_t n = co_await asio::async_write(
        ssl_, buffers, asio::redirect_error(asio::use_awaitable, ec));
    if (ec)
        co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
    co_return n;
}

asio::awaitable<Result<void>> TlsStream::shutdown() {
    // async_shutdown sends our close_notify and then waits for the peer's. It ends
    // with eof or stream_truncated when the peer's side had already ended, and fails
    // with "application data after close notify" when the peer is still sending:
    // that data is discarded at the TCP level until the peer ends.
    asio::error_code ec;
    co_await ssl_.async_shutdown(asio::redirect_error(asio::use_awaitable, ec));
    if (!ec || ec == asio::error::eof || ec == asio::ssl::error::stream_truncated)
        co_return std::expected<void, TAPSError>{std::in_place};
    if (ec.category() == asio::error::get_ssl_category() &&
        ERR_GET_REASON(static_cast<unsigned long>(ec.value())) == SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY)
        co_return co_await drain_until_eof(ssl_.next_layer());
    co_return std::unexpected(io_error(ErrorEvent::CONNECTION_ERROR, ec));
}

}  // namespace taps
