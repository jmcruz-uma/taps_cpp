#pragma once

#include "taps/taps_api.h"
#include "security/security_provider.h"

#include <asio/experimental/channel.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

#include <memory>

namespace taps {

// ============================================================================
// SecureAcceptor (private)
//
// Accepts TCP connections for a Listener with security and secures each one in
// its own coroutine, so the handshakes of concurrent clients run in parallel.
// A Connection is delivered once its handshake completes (RFC 9623 Section 4.3
// lets a TLS-over-TCP connection count as established after the TLS handshake),
// in the order the handshakes finish; one that fails is dropped (RFC 9622
// Section 7.2: not a Listener error).
//
// Shared by the TCPListener, its accept loop and the handshakes in flight, each
// holding a reference, so none of them outlives what it uses. The accept loop and
// the channel of established Connections are touched only on strand_; the
// handshakes run on the io_context's executor.
// ============================================================================
class SecureAcceptor : public std::enable_shared_from_this<SecureAcceptor> {
public:
    SecureAcceptor(asio::ip::tcp::acceptor acceptor, std::unique_ptr<SecurityProvider> provider,
                   MessageMemoryConfig memory);

    // Starts the accept loop.
    void start();

    // The next established Connection. Fails once the acceptor has stopped.
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept();

    // No more connections; a pending accept() fails. Handshakes in flight finish,
    // and their Connections are dropped.
    void stop();

    asio::ip::tcp::endpoint local_endpoint() const;

private:
    asio::awaitable<void> accept_loop();
    asio::awaitable<void> secure(asio::ip::tcp::socket socket);

    asio::ip::tcp::acceptor acceptor_;
    asio::strand<asio::any_io_executor> strand_;
    std::unique_ptr<SecurityProvider> provider_;
    MessageMemoryConfig memory_;
    asio::experimental::channel<void(std::error_code, std::unique_ptr<TCPConnection>)> ready_;
};

}  // namespace taps
