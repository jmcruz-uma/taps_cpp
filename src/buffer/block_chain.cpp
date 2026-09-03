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

BlockChain BlockChain::first(std::size_t len) const {
    BlockChain out;
    len = std::min(len, size_);
    for (const BlockRef& r : blocks_) {
        if (len == 0)
            break;
        const std::size_t take = std::min(r.size(), len);
        BlockRef piece = r;  // shares the block by reference count
        piece.set_range(r.begin_offset(), r.begin_offset() + take);
        out.append(std::move(piece));
        len -= take;
    }
    return out;
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
