#pragma once

#include "buffer/block.h"

#include <cstddef>
#include <deque>
#include <span>

namespace taps {

// ============================================================================
// BlockChain
// ============================================================================
//
// An ordered sequence of BlockRefs forming one logical byte run — the substrate
// for a received Message (mode C, "one Message") and for the deframer receive
// cursor of RFC 9623 section 6.
//
// Data is appended at the back as it arrives (HandleReceivedData); consume_front()
// advances a read cursor from the front (AdvanceReceiveCursor), releasing blocks
// back to their pool as they are fully consumed. append() and consume_front() copy
// no payload bytes; only copy_to() does.
class BlockChain {
public:
    BlockChain() = default;

    // Appends `ref` to the back. Empty / invalid refs are ignored.
    void append(BlockRef ref);

    bool        empty()       const noexcept { return size_ == 0; }
    std::size_t size()        const noexcept { return size_; }            // live bytes
    std::size_t block_count() const noexcept { return blocks_.size(); }

    // Iteration over the constituent BlockRefs, front to back.
    auto begin() const noexcept { return blocks_.begin(); }
    auto end()   const noexcept { return blocks_.end(); }

    // Advances the read cursor by `n` bytes from the front (clamped to size()).
    // Fully-consumed blocks are dropped and released to their pool; a straddled
    // block has its begin advanced in place.
    void consume_front(std::size_t n);

    // Copies the whole chain into `out` (out.size() must be >= size()).
    // Returns the number of bytes written.
    std::size_t copy_to(std::span<std::byte> out) const;

private:
    std::deque<BlockRef> blocks_;
    std::size_t          size_ = 0;
};

}  // namespace taps
