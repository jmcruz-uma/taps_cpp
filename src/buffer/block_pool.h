#pragma once

#include "buffer/block.h"

#include <cstddef>

namespace taps {

// ============================================================================
// BlockPool — allocation strategy interface
// ============================================================================
//
// How a Connection obtains and returns the fixed-size DataBlocks its receive
// path is built from. Spiritually ACE_Allocator: one abstract contract, several
// interchangeable strategies. Only HeapBlockPool (a straightforward free-list
// allocator that falls back to `new`) ships today; an arena- or std::pmr-backed
// strategy can be added later as a sibling, without touching any caller — they
// only ever see BlockPool, never the concrete type.
//
// `block_size` is a syscall-batching / cache-locality knob, never a bound on
// Message size: a chain simply grows another block.
class BlockPool {
public:
    virtual ~BlockPool() = default;

    // A fresh block with an empty live window [0, 0), ready to be filled. Returns
    // an invalid (falsey) BlockRef when the strategy is out of capacity (e.g. a
    // live-block cap used for backpressure).
    virtual BlockRef acquire() = 0;

    virtual std::size_t block_size() const noexcept = 0;
    virtual bool        at_capacity() const noexcept = 0;

    // Introspection (tests / metrics).
    virtual std::size_t free_blocks() const noexcept = 0;
    virtual std::size_t live_blocks() const noexcept = 0;

private:
    friend class DataBlock;
    virtual void recycle(DataBlock* blk) noexcept = 0;
};

}  // namespace taps
