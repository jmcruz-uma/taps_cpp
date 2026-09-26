#pragma once

#include "buffer/block.h"

#include <cstddef>
#include <memory>
#include <memory_resource>
#include <utility>
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
// back to the resource as they are fully consumed. append() and consume_front() copy
// no payload bytes; only copy_to() does.
class BlockChain {
public:
    BlockChain() noexcept = default;
    BlockChain(const BlockChain& other);
    BlockChain(BlockChain&& other) noexcept;
    BlockChain& operator=(const BlockChain& other);
    BlockChain& operator=(BlockChain&& other) noexcept;
    ~BlockChain();

    // Appends `ref` to the back. Empty / invalid refs are ignored. A ref that
    // continues the last one inside the same block extends it instead of adding an
    // entry, so there is one entry per block however many reads filled it.
    void append(BlockRef ref);

    bool        empty()       const noexcept { return size_ == 0; }
    std::size_t size()        const noexcept { return size_; }     // live bytes
    std::size_t block_count() const noexcept { return count_; }

    // The message memory resource of the chain's blocks, or nullptr for an empty
    // chain. All blocks of a chain come from one Connection's pool, hence one
    // resource. Used for message memory derived from the chain (its own entry
    // storage beyond the inline capacity, a Message's contiguous as_bytes() buffer).
    std::pmr::memory_resource* resource() const noexcept {
        return count_ == 0 ? nullptr : data_[head_].block()->resource();
    }

    // Iteration over the constituent BlockRefs, front to back.
    const BlockRef* begin() const noexcept { return data_ + head_; }
    const BlockRef* end()   const noexcept { return data_ + head_ + count_; }

    // Advances the read cursor by `n` bytes from the front (clamped to size()).
    // Fully-consumed blocks are dropped and released; a straddled block has its
    // begin advanced in place.
    void consume_front(std::size_t n);

    // A new chain over the first `len` bytes (clamped to size()), sharing the
    // underlying blocks by reference count. Does not consume from *this.
    // RFC 9623 section 6 DeliverAndAdvanceReceiveCursor.
    BlockChain first(std::size_t len) const;

    // Copies the whole chain into `out` (out.size() must be >= size()).
    // Returns the number of bytes written.
    std::size_t copy_to(std::span<std::byte> out) const;

private:
    // Entries live inline up to kInline; beyond that in storage from the blocks'
    // resource. [head_, head_ + count_) are live; consume_front() advances head_.
    static constexpr std::size_t kInline = 2;

    bool inline_storage() const noexcept { return data_ == inline_; }
    void push_back(BlockRef ref);
    void grow();
    void clear() noexcept;
    void release_storage() noexcept;

    BlockRef                   inline_[kInline];
    BlockRef*                  data_ = inline_;
    std::size_t                capacity_ = kInline;
    std::size_t                head_ = 0;
    std::size_t                count_ = 0;
    std::size_t                size_ = 0;
    std::pmr::memory_resource* storage_resource_ = nullptr;   // owner of non-inline storage
};

// A chain held by a Message: the object itself comes from the message resource.
template <typename... Args>
std::shared_ptr<BlockChain> make_chain(std::pmr::memory_resource* resource, Args&&... args) {
    return std::allocate_shared<BlockChain>(std::pmr::polymorphic_allocator<BlockChain>(resource),
                                            std::forward<Args>(args)...);
}

}  // namespace taps
