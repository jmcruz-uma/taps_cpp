#pragma once

#include "taps/taps_api.h"   // unlimited_connections

#include <atomic>
#include <cstddef>

namespace taps {

// How many more Connections a Listener may deliver (RFC 9622 Section 7.2,
// SetNewConnectionLimit). Shared by the Listener and whatever delivers its
// Connections, which may outlive it. Safe to use from any thread.
//
// Consulted once per new Connection, never per message; without a limit, take()
// is a single load.
class NewConnectionLimit {
public:
    void set(std::size_t limit) noexcept { value_.store(limit, std::memory_order_relaxed); }

    // Takes one delivery; false if none is left.
    bool take() noexcept {
        std::size_t n = value_.load(std::memory_order_relaxed);
        while (n != unlimited_connections) {
            if (n == 0)
                return false;
            if (value_.compare_exchange_weak(n, n - 1, std::memory_order_relaxed))
                return true;
        }
        return true;
    }

    // Returns a delivery taken for a Connection that was not delivered after all.
    void give_back() noexcept {
        std::size_t n = value_.load(std::memory_order_relaxed);
        while (n != unlimited_connections &&
               !value_.compare_exchange_weak(n, n + 1, std::memory_order_relaxed)) {
        }
    }

private:
    std::atomic<std::size_t> value_{unlimited_connections};
};

}  // namespace taps
