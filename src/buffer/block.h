#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

namespace taps {

class BlockPool;

// ============================================================================
// DataBlock
// ============================================================================
//
// Reference-counted fixed-size byte storage. Instances are created and owned by a
// BlockPool; when the last reference is dropped the block returns to its pool's
// free list (or is deleted if the pool's free list is full or the pool is gone).
//
// The reference count is atomic, so a Message backed by these blocks may be moved
// to another thread for consumption. The storage is allocated with
// make_unique_for_overwrite: it is never zero-filled (RFC 9623 receive path only
// writes the bytes it actually received).
//
// The owning BlockPool must outlive every block it hands out (same contract as a
// std::pmr memory resource).
class DataBlock {
public:
    DataBlock(BlockPool* pool, std::size_t capacity)
        : pool_(pool),
          capacity_(capacity),
          storage_(std::make_unique_for_overwrite<std::byte[]>(capacity)) {}

    std::byte*       data()       noexcept { return storage_.get(); }
    const std::byte* data() const noexcept { return storage_.get(); }
    std::size_t      capacity() const noexcept { return capacity_; }

    void add_ref() noexcept {
        refcount_.fetch_add(1, std::memory_order_relaxed);
    }
    void release() noexcept;  // defined in block_pool.cpp (needs BlockPool)

    std::uint32_t use_count() const noexcept {
        return refcount_.load(std::memory_order_acquire);
    }

private:
    friend class BlockPool;

    BlockPool*                   pool_;                  // nullptr detaches the block
    std::atomic<std::uint32_t>   refcount_{0};
    std::size_t                  capacity_;
    DataBlock*                   next_free_ = nullptr;   // free-list link, idle only
    std::unique_ptr<std::byte[]> storage_;
};

// ============================================================================
// BlockRef
// ============================================================================
//
// A counted handle to a DataBlock together with the [begin, end) sub-range of it
// that is currently live. This is the node type of a BlockChain: a slice that
// straddles a block boundary shares the straddled block with the original chain
// through the reference count (RFC 9623 section 6 DeliverAndAdvanceReceiveCursor).
class BlockRef {
public:
    BlockRef() noexcept = default;

    BlockRef(DataBlock* blk, std::size_t begin, std::size_t end) noexcept
        : blk_(blk), begin_(begin), end_(end) {
        if (blk_) blk_->add_ref();
    }

    BlockRef(const BlockRef& o) noexcept
        : blk_(o.blk_), begin_(o.begin_), end_(o.end_) {
        if (blk_) blk_->add_ref();
    }
    BlockRef(BlockRef&& o) noexcept
        : blk_(std::exchange(o.blk_, nullptr)), begin_(o.begin_), end_(o.end_) {}

    BlockRef& operator=(const BlockRef& o) noexcept {
        if (this != &o) {
            if (o.blk_) o.blk_->add_ref();
            reset();
            blk_ = o.blk_;
            begin_ = o.begin_;
            end_ = o.end_;
        }
        return *this;
    }
    BlockRef& operator=(BlockRef&& o) noexcept {
        if (this != &o) {
            reset();
            blk_ = std::exchange(o.blk_, nullptr);
            begin_ = o.begin_;
            end_ = o.end_;
        }
        return *this;
    }
    ~BlockRef() { reset(); }

    void reset() noexcept {
        if (blk_) {
            blk_->release();
            blk_ = nullptr;
        }
        begin_ = end_ = 0;
    }

    explicit operator bool() const noexcept { return blk_ != nullptr; }
    bool valid() const noexcept { return blk_ != nullptr; }

    std::size_t size()  const noexcept { return end_ - begin_; }
    bool        empty() const noexcept { return begin_ == end_; }

    const std::byte*           data()  const noexcept { return blk_->data() + begin_; }
    std::span<const std::byte>  bytes() const noexcept { return {data(), size()}; }

    // Mutable access to the underlying block, for the receive path that fills it.
    std::byte*  writable_data()          noexcept { return blk_->data() + begin_; }
    std::size_t capacity_after_begin() const noexcept {
        return blk_->capacity() - begin_;
    }

    // Narrow / move the live window within the same block (no re-reference).
    void set_range(std::size_t begin, std::size_t end) noexcept {
        begin_ = begin;
        end_ = end;
    }
    void advance_begin(std::size_t n) noexcept { begin_ += n; }

    std::size_t begin_offset() const noexcept { return begin_; }
    std::size_t end_offset()   const noexcept { return end_; }
    DataBlock*  block()        const noexcept { return blk_; }

private:
    DataBlock*  blk_ = nullptr;
    std::size_t begin_ = 0;
    std::size_t end_ = 0;
};

}  // namespace taps
