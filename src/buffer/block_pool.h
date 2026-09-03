#pragma once

#include "buffer/block.h"

#include <cstddef>
#include <mutex>

namespace taps {

// ============================================================================
// BlockPool
// ============================================================================
//
// A capacity-bounded free-list allocator of fixed-size DataBlocks, spiritually
// the same as ACE_Dynamic_Cached_Allocator: released blocks are kept on a free
// list up to `max_free_blocks`; beyond that they are freed. Allocation beyond the
// free list falls back to `new`.
//
// `max_live_blocks` (0 == unlimited) bounds the number of blocks checked out at
// once. acquire() returns an invalid BlockRef when that cap is reached; the
// receive path uses this as the signal to stop issuing reads (backpressure for
// unreliable transports, where the transport itself provides none).
//
// Thread-safety: one BlockPool belongs to one Connection; acquire() and recycle()
// (the latter invoked when a BlockRef's count hits zero) normally run on that
// Connection's executor, so the internal mutex is uncontended. It is there only
// to keep the free list consistent for the one case that can cross threads: a
// BlockRef retained by the application past receive() and released on another
// thread. No allocation happens under the mutex (new / delete are kept outside
// the critical section) and it is never held across a co_await. The pool must
// outlive every block it hands out.
//
// `block_size` is a syscall-batching / cache-locality knob, never a bound on
// Message size: a chain simply grows another block.
class BlockPool {
public:
    static constexpr std::size_t kDefaultBlockSize = 64 * 1024;
    static constexpr std::size_t kDefaultMaxFreeBlocks = 64;

    explicit BlockPool(std::size_t block_size = kDefaultBlockSize,
                       std::size_t max_free_blocks = kDefaultMaxFreeBlocks,
                       std::size_t max_live_blocks = 0);
    ~BlockPool();

    BlockPool(const BlockPool&) = delete;
    BlockPool& operator=(const BlockPool&) = delete;

    // A fresh block with an empty live window [0, 0), ready to be filled. Returns
    // an invalid (falsey) BlockRef when the live cap has been reached.
    BlockRef acquire();

    std::size_t block_size() const noexcept { return block_size_; }
    bool        at_capacity() const noexcept;

    // Introspection (tests / metrics).
    std::size_t free_blocks() const noexcept;
    std::size_t live_blocks() const noexcept;

private:
    friend class DataBlock;
    void recycle(DataBlock* blk) noexcept;

    mutable std::mutex mtx_;
    std::size_t        block_size_;
    std::size_t        max_free_blocks_;
    std::size_t        max_live_blocks_;
    DataBlock*         free_list_ = nullptr;
    std::size_t        free_count_ = 0;
    std::size_t        live_count_ = 0;
};

}  // namespace taps
