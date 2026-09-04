#pragma once

#include "buffer/block_pool.h"

#include <mutex>

namespace taps {

// ============================================================================
// HeapBlockPool
// ============================================================================
//
// The only BlockPool strategy shipped today: a capacity-bounded free-list
// allocator of fixed-size DataBlocks, spiritually the same as
// ACE_Dynamic_Cached_Allocator. Released blocks are kept on a free list up to
// `max_free_blocks`; beyond that they are freed. Allocation beyond the free
// list falls back to `new`.
//
// `max_live_blocks` (0 == unlimited) bounds the number of blocks checked out at
// once. acquire() returns an invalid BlockRef when that cap is reached; the
// receive path uses this as the signal to stop issuing reads (backpressure for
// unreliable transports, where the transport itself provides none).
//
// acquire() still falls back to `new` the first time it outgrows a still-empty
// free list — call warm_up() once, before traffic flows, to avoid that.
//
// Thread-safety: one HeapBlockPool belongs to one Connection; acquire() and
// recycle() (the latter invoked when a BlockRef's count hits zero) normally run
// on that Connection's executor, so the internal mutex is uncontended. It is
// there only to keep the free list consistent for the one case that can cross
// threads: a BlockRef retained by the application past receive() and released
// on another thread. No allocation happens under the mutex (new / delete are
// kept outside the critical section) and it is never held across a co_await.
// The pool must outlive every block it hands out.
class HeapBlockPool final : public BlockPool {
public:
    static constexpr std::size_t kDefaultBlockSize = 64 * 1024;
    static constexpr std::size_t kDefaultMaxFreeBlocks = 64;

    explicit HeapBlockPool(std::size_t block_size = kDefaultBlockSize,
                           std::size_t max_free_blocks = kDefaultMaxFreeBlocks,
                           std::size_t max_live_blocks = 0);
    ~HeapBlockPool() override;

    HeapBlockPool(const HeapBlockPool&) = delete;
    HeapBlockPool& operator=(const HeapBlockPool&) = delete;

    BlockRef acquire() override;

    std::size_t block_size() const noexcept override { return block_size_; }
    bool        at_capacity() const noexcept override;

    std::size_t free_blocks() const noexcept override;
    std::size_t live_blocks() const noexcept override;

    // Eagerly mints DataBlocks and parks them on the free list until it holds
    // `count` (clamped to max_free_blocks — the list never retains more than
    // that anyway), so later acquire() calls pull from the free list instead of
    // hitting `new`. Call it once, at setup, before traffic flows: that is the
    // guarantee most real-time/embedded coding standards actually ask for —
    // dynamic allocation at init is fine, allocation once the hot path is
    // running is not. It does nothing useful once blocks are already checked
    // out and cycling (a live block isn't free to pre-populate with).
    void warm_up(std::size_t count);

private:
    void recycle(DataBlock* blk) noexcept override;

    mutable std::mutex mtx_;
    std::size_t        block_size_;
    std::size_t        max_free_blocks_;
    std::size_t        max_live_blocks_;
    DataBlock*         free_list_ = nullptr;
    std::size_t        free_count_ = 0;
    std::size_t        live_count_ = 0;
};

}  // namespace taps
