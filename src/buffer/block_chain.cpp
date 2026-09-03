#include "buffer/block_chain.h"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace taps {

void BlockChain::append(BlockRef ref) {
    if (!ref || ref.empty())
        return;
    size_ += ref.size();
    blocks_.push_back(std::move(ref));
}

void BlockChain::consume_front(std::size_t n) {
    n = std::min(n, size_);
    size_ -= n;
    while (n > 0) {
        BlockRef& front = blocks_.front();
        const std::size_t avail = front.size();
        if (n < avail) {
            front.advance_begin(n);
            n = 0;
        } else {
            n -= avail;
            blocks_.pop_front();
        }
    }
    // Defensive: append() rejects empty refs, but a consume that lands exactly on
    // a boundary can leave the loop with a now-empty leading block untouched only
    // if size_ accounting drifts; keep the invariant explicit.
    while (!blocks_.empty() && blocks_.front().empty())
        blocks_.pop_front();
}

std::size_t BlockChain::copy_to(std::span<std::byte> out) const {
    assert(out.size() >= size_);
    std::size_t off = 0;
    for (const BlockRef& r : blocks_) {
        const std::span<const std::byte> b = r.bytes();
        std::memcpy(out.data() + off, b.data(), b.size());
        off += b.size();
    }
    return off;
}

}  // namespace taps
