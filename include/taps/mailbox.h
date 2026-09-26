#pragma once

#include <asio/any_io_executor.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <memory_resource>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace taps {

class BlockChain;  // src/buffer/block_chain.h (private) — one datagram per chain

// ==============================
// Mailbox (internal use only)
// ==============================
//
// Per-logical-UDP-connection queue of received datagrams. Each datagram is a
// single-block BlockChain from the UDP Listener's message blocks; nothing here
// copies the payload.
//
// The queue is a bounded ring. UDP has no transport flow control, so when a slow
// consumer lets the ring fill, deliver() drops the OLDEST datagram and bumps a
// counter (RFC 9621 rationale for unreliable + unordered delivery). It never
// blocks and never queues without bound. The ring's storage grows with the
// backlog actually seen, up to the bound, and is kept: once the Connection's
// usual backlog fits, no datagram allocates. The storage holds references to
// message data, so it comes from the message memory resource.
//
// Everything except dropped() runs on the executor passed to the constructor
// (the listener strand), so no locking is needed. A receiver goes to that
// executor, then try_pop(); if nothing is there and the Mailbox is open, it
// co_awaits wait() and tries again, back on that executor. dropped() may be read
// from any thread (atomic).
class Mailbox {
public:
    using value_type = std::shared_ptr<BlockChain>;

    // Why the Mailbox was closed.
    enum class CloseCause {
        owner,      // the connection was closed or aborted locally
        idle,       // no traffic for longer than the listener's idle timeout
        displaced   // evicted to make room for a new source (bounded table)
    };

    Mailbox(asio::any_io_executor exec, std::pmr::memory_resource* resource,
            std::size_t capacity = 256)
        : exec_(std::move(exec))
        , timer_(exec_)
        , ring_(std::pmr::polymorphic_allocator<value_type>(resource))
        , capacity_(capacity ? capacity : 1)
    {
        timer_.expires_at(std::chrono::steady_clock::time_point::max());
    }

    const asio::any_io_executor& executor() const noexcept { return exec_; }

    void deliver(value_type datagram) {
        if (closed_)
            return;
        if (count_ == capacity_) {
            pop_front();                                     // drop-oldest
            dropped_.fetch_add(1, std::memory_order_relaxed);
        } else if (count_ == ring_.size()) {
            grow();
        }
        ring_[(head_ + count_) % ring_.size()] = std::move(datagram);
        ++count_;
        timer_.cancel_one();                                 // wake a waiter, if any
    }

    // The oldest datagram, or null if none is queued.
    value_type try_pop() noexcept {
        return count_ == 0 ? value_type{} : pop_front();
    }

    // Completes when a datagram arrives or the Mailbox is closed.
    asio::awaitable<std::tuple<std::error_code>> wait() {
        return timer_.async_wait(asio::as_tuple(asio::use_awaitable));
    }

    void close(CloseCause cause = CloseCause::owner) {
        if (!closed_)
            cause_ = cause;
        closed_ = true;
        timer_.cancel();
    }

    bool closed() const noexcept { return closed_; }
    CloseCause close_cause() const noexcept { return cause_; }

    std::size_t dropped() const noexcept {
        return dropped_.load(std::memory_order_relaxed);
    }

private:
    value_type pop_front() noexcept {
        value_type d = std::move(ring_[head_]);
        head_ = (head_ + 1) % ring_.size();
        --count_;
        return d;
    }

    // Doubles the storage (at most to the bound), keeping the order of the queue.
    void grow() {
        std::pmr::vector<value_type> bigger(ring_.get_allocator());
        bigger.resize(std::min(capacity_, std::max<std::size_t>(4, ring_.size() * 2)));
        for (std::size_t i = 0; i < count_; ++i)
            bigger[i] = std::move(ring_[(head_ + i) % ring_.size()]);
        ring_ = std::move(bigger);
        head_ = 0;
    }

    asio::any_io_executor         exec_;
    asio::steady_timer            timer_;
    std::pmr::vector<value_type>  ring_;       // circular; [head_, head_ + count_) queued
    std::size_t                   head_ = 0;
    std::size_t                   count_ = 0;
    std::size_t                   capacity_;
    std::atomic<std::size_t>      dropped_{0};
    bool                          closed_ = false;
    CloseCause                    cause_ = CloseCause::owner;
};

} // namespace taps
