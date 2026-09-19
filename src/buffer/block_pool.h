#pragma once

#include "buffer/block.h"

#include <cstddef>
#include <memory>

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

    // The strategy's answer for a single contiguous buffer of `n` bytes, used only
    // by Message::ensure_gathered() when a chain spans more than one block and the
    // caller asked for it as_bytes(). This is a DIFFERENT allocation shape than
    // acquire()'s fixed block_size() blocks — it exists so a workload-aware
    // application can redirect it too (a static arena, a std::pmr resource, ...),
    // not because every BlockPool strategy needs its own answer: the default here
    // is exactly what every caller got before this hook existed (a plain heap
    // allocation), so a strategy that doesn't care about this allocation shape
    // needs no override at all. Not pure virtual on purpose — unlike acquire() /
    // block_size() / at_capacity(), a concrete strategy has a perfectly good
    // default and forcing every future strategy to restate it would be the kind of
    // boilerplate this interface otherwise avoids.
    virtual std::shared_ptr<std::byte[]> allocate_contiguous(std::size_t n) const {
        return std::shared_ptr<std::byte[]>(new std::byte[n]);
    }

private:
    friend class DataBlock;
    virtual void recycle(DataBlock* blk) noexcept = 0;
};

}  // namespace taps
