#pragma once

#include <asio/any_io_executor.hpp>
#include <asio/dispatch.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <deque>
#include <memory>
#include <system_error>

namespace taps {

class BlockChain;  // src/buffer/block_chain.h (private) — one datagram per chain

// ==============================
// Mailbox (internal use only)
// ==============================
//
// Per-logical-UDP-connection queue of received datagrams. Each datagram is a
// single-block BlockChain drawn from the UDPListener's BlockPool; nothing here
// copies the payload.
//
// The queue is a bounded ring. UDP has no transport flow control, so when a slow
// consumer lets the ring fill, deliver() drops the OLDEST datagram and bumps a
// counter (RFC 9621 rationale for unreliable + unordered delivery). It never
// blocks and never queues without bound.
//
// deliver() and receive() both run on the executor passed to the constructor
// (the listener strand); no locking is needed between them. dropped() may be read
// from any thread (atomic).
class Mailbox {
public:
    using value_type = std::shared_ptr<BlockChain>;

    explicit Mailbox(asio::any_io_executor exec, std::size_t capacity = 256)
        : exec_(std::move(exec))
        , timer_(exec_)
        , capacity_(capacity ? capacity : 1)
    {
        timer_.expires_at(std::chrono::steady_clock::time_point::max());
    }

    void deliver(value_type datagram) {
        if (closed_)
            return;
        if (ring_.size() >= capacity_) {
            ring_.pop_front();                               // drop-oldest
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        ring_.push_back(std::move(datagram));
        timer_.cancel_one();                                 // wake a waiter, if any
    }

    asio::awaitable<value_type> receive() {
        co_await asio::dispatch(exec_, asio::use_awaitable); // serialise with deliver()
        for (;;) {
            if (!ring_.empty()) {
                value_type d = std::move(ring_.front());
                ring_.pop_front();
                co_return d;
            }
            if (closed_)
                throw std::system_error(
                    std::make_error_code(std::errc::operation_canceled));
            asio::error_code ec;
            co_await timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        }
    }

    void close() {
        closed_ = true;
        timer_.cancel();
    }

    std::size_t dropped() const noexcept {
        return dropped_.load(std::memory_order_relaxed);
    }

private:
    asio::any_io_executor      exec_;
    asio::steady_timer         timer_;
    std::deque<value_type>     ring_;
    std::size_t                capacity_;
    std::atomic<std::size_t>   dropped_{0};
    bool                       closed_ = false;
};

} // namespace taps
