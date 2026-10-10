#pragma once

#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "transport/const_buffer_sequence.h"

#include <asio/experimental/channel.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/strand.hpp>

#include <cstddef>
#include <memory>
#include <system_error>
#include <tuple>
#include <unordered_map>

namespace taps {

class MessageBlockPool;
class NewConnectionLimit;

// ============================================================================
// UDPDemux (private)
//
// The bound socket, the demultiplexing table and the receive loop behind a UDP
// Listener (RFC 9623 Section 4.7.2). Incoming datagrams are matched by source
// endpoint to per-Connection Mailboxes; a datagram from a source with no
// Connection creates one while the Listener accepts.
//
// Shared by the UDPListener, its receive loop and every PassiveUDPConnection,
// each holding a reference: a Connection outlives its Listener, as a TCP
// Connection does. Once the Listener has stopped (stop() or destruction) and no
// source is left in the table, the socket closes, the receive loop ends, and the
// last Connection to go releases the rest.
//
// A Connection ends only when the application closes or destroys it: there is no
// idle timeout, so a peer that sends rarely keeps its Connection. The table holds
// at most connection_ceiling() sources; beyond that, a datagram from a new source
// is dropped without creating any state, and no existing Connection is evicted.
// This keeps memory bounded under a spoofed-source flood without attempting
// address validation (out of scope).
//
// The table, every Mailbox, the accept channel and the socket's asynchronous
// operations are touched only on strand_.
// ============================================================================
class UDPDemux : public std::enable_shared_from_this<UDPDemux> {
public:
    UDPDemux(asio::io_context& ctx, std::unique_ptr<MessageBlockPool> pool,
             std::shared_ptr<NewConnectionLimit> limit);
    ~UDPDemux();

    // Binds the socket and starts the receive loop.
    Result<void> start(const asio::ip::udp::endpoint& local);

    // The next new source, as a Connection. Fails once accepting has stopped.
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept();

    // No new sources from now on; existing Connections are unaffected.
    void stop_accepting();

    // The Connection that owns `mailbox` is gone (closed or destroyed): its
    // source leaves the table, so a later datagram from it creates a new one.
    void release(const asio::ip::udp::endpoint& source, const Mailbox* mailbox);

    // Sends one datagram to `to` on the shared socket. Every PassiveUDPConnection
    // of the Listener sends through here, from its own coroutine (on any thread).
    // asio allows one socket object to be used from several threads at once only
    // for its synchronous operations, so the send starts on strand_, like every
    // other operation on the socket; several sends may be pending at once, queued
    // by the socket. `datagram` must stay alive until the send completes.
    asio::awaitable<std::tuple<std::error_code, std::size_t>>
    send_to(const ConstBufferSequence& datagram, const asio::ip::udp::endpoint& to);

    // The endpoint the socket is bound to, recorded by start(): callers on any
    // thread read it without touching the socket.
    const asio::ip::udp::endpoint& local_endpoint() const noexcept { return local_; }

private:
    asio::awaitable<void> receive_loop();
    // Closes the socket once nothing can use it any more.
    void shut_down_if_unused();

    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint local_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::unique_ptr<MessageBlockPool> pool_;   // one block per datagram
    std::shared_ptr<NewConnectionLimit> limit_; // the Listener's (RFC 9622 Section 7.2)
    asio::experimental::channel<void(std::error_code, std::unique_ptr<PassiveUDPConnection>)>
        accept_channel_;

    std::unordered_map<asio::ip::udp::endpoint, std::shared_ptr<Mailbox>> table_;
    bool accepting_ = true;
};

}  // namespace taps
