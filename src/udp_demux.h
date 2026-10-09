#pragma once

#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include "transport/const_buffer_sequence.h"

#include <asio/experimental/channel.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>

#include <chrono>
#include <cstddef>
#include <list>
#include <memory>
#include <system_error>
#include <tuple>
#include <unordered_map>

namespace taps {

class MessageBlockPool;

// ============================================================================
// UDPDemux (private)
//
// The bound socket, the demultiplexing table and the receive loop behind a UDP
// Listener (RFC 9623 Section 4.7.2). Incoming datagrams are matched by source
// endpoint to per-Connection Mailboxes; a datagram from a source with no
// Connection creates one while the Listener accepts.
//
// Shared by the UDPListener, its two coroutines (receive loop, idle sweep) and
// every PassiveUDPConnection, each holding a reference: a Connection outlives its
// Listener, as a TCP Connection does. Once the Listener has stopped (stop() or
// destruction) and no source is left in the table, the socket closes, the
// coroutines end, and the last Connection to go releases the rest.
//
// The table is a bounded LRU: a new source beyond the limit displaces the
// least-recently-active one, and an idle sweep evicts sources quiet for longer
// than the idle timeout. This keeps memory bounded under a spoofed-source flood
// without attempting address validation (out of scope).
//
// The table, every Mailbox, the accept channel and the socket's asynchronous
// operations are touched only on strand_.
// ============================================================================
class UDPDemux : public std::enable_shared_from_this<UDPDemux> {
public:
    UDPDemux(asio::io_context& ctx, std::unique_ptr<MessageBlockPool> pool);
    ~UDPDemux();

    // Binds the socket and starts the receive loop and the idle sweep.
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

    // The shared socket, for its local endpoint; sends go through send_to().
    asio::ip::udp::socket& socket() noexcept { return socket_; }

private:
    struct Entry {
        asio::ip::udp::endpoint               source;
        std::shared_ptr<Mailbox>              mailbox;
        std::chrono::steady_clock::time_point last_active;
    };
    using Lru = std::list<Entry>;

    asio::awaitable<void> receive_loop();
    asio::awaitable<void> sweep_loop();
    void evict(Lru::iterator it, Mailbox::CloseCause cause);
    // Closes the socket once nothing can use it any more.
    void shut_down_if_unused();

    asio::ip::udp::socket socket_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::unique_ptr<MessageBlockPool> pool_;   // one block per datagram
    asio::steady_timer sweep_timer_;
    asio::experimental::channel<void(std::error_code, std::unique_ptr<PassiveUDPConnection>)>
        accept_channel_;

    Lru lru_;                                  // most recently active first
    std::unordered_map<asio::ip::udp::endpoint, Lru::iterator> index_;
    bool accepting_ = true;
};

}  // namespace taps
