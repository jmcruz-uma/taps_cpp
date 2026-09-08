#include "security/tls_stream.h"

#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <openssl/ssl.h>

namespace taps {

asio::awaitable<Result<void>> TlsStream::handshake_client(std::string server_name) {
    if (!server_name.empty()) {
        // SNI: tell the server which name we expect, so it can pick the right cert.
        if (::SSL_set_tlsext_host_name(ssl_.native_handle(), server_name.c_str()) != 1) {
            co_return std::unexpected(
                TAPSError{ErrorType::INTERNAL_ERROR, "failed to set TLS SNI host name"});
        }
        // Validate the presented certificate against the same name.
        asio::error_code vc_ec;
        ssl_.set_verify_callback(asio::ssl::host_name_verification(server_name), vc_ec);
        if (vc_ec) {
            co_return std::unexpected(
                TAPSError{ErrorType::INTERNAL_ERROR, "set_verify_callback: " + vc_ec.message()});
        }
    }

    asio::error_code ec;
    co_await ssl_.async_handshake(asio::ssl::stream_base::client,
                                 asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return std::unexpected(
            TAPSError{ErrorType::CONNECTION_FAILED, "TLS handshake failed: " + ec.message()});
    }
    co_return std::expected<void, TAPSError>{std::in_place};
}

asio::awaitable<Result<void>> TlsStream::handshake_server() {
    asio::error_code ec;
    co_await ssl_.async_handshake(asio::ssl::stream_base::server,
                                 asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return std::unexpected(
            TAPSError{ErrorType::CONNECTION_FAILED, "TLS handshake failed: " + ec.message()});
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

asio::awaitable<Result<std::size_t>> TlsStream::read_some(asio::mutable_buffer buffer) {
    asio::error_code ec;
    const std::size_t n = co_await ssl_.async_read_some(
        buffer, asio::redirect_error(asio::use_awaitable, ec));
    // A clean close_notify surfaces as eof; a peer that dropped the TCP connection
    // without one surfaces as stream_truncated. For a byte-stream consumer both
    // mean "no more data".
    if (ec == asio::error::eof || ec == asio::ssl::error::stream_truncated)
        co_return std::size_t{0};
    if (ec)
        co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
    co_return n;
}

asio::awaitable<Result<std::size_t>> TlsStream::write(
    std::span<const asio::const_buffer> buffers) {
    asio::error_code ec;
    const std::size_t n = co_await asio::async_write(
        ssl_, buffers, asio::redirect_error(asio::use_awaitable, ec));
    if (ec)
        co_return std::unexpected(TAPSError{ErrorType::CONNECTION_FAILED, ec.message()});
    co_return n;
}

asio::awaitable<Result<void>> TlsStream::shutdown() {
    // Sends our close_notify. asio's async_shutdown also waits for the peer's;
    // for the cooperating peers in this benchmark that returns promptly, and
    // TCPConnection::close() hard-closes the socket straight after regardless.
    // eof / stream_truncated here just mean the peer already went away.
    asio::error_code ec;
    co_await ssl_.async_shutdown(asio::redirect_error(asio::use_awaitable, ec));
    if (ec && ec != asio::error::eof && ec != asio::ssl::error::stream_truncated) {
        co_return std::unexpected(TAPSError{ErrorType::INTERNAL_ERROR, ec.message()});
    }
    co_return std::expected<void, TAPSError>{std::in_place};
}

}  // namespace taps
