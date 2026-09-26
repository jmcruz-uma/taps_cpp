#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <span>
#include <utility>

namespace taps {

// ============================================================================
// DataBlock
// ============================================================================
//
// Reference-counted fixed-size byte storage for received message data. The
// header and the payload are two allocations from the message memory resource:
// a payload of exactly the block size stays in the resource's size class for
// that size (a pool resource recycles it), and it is never zero-filled (the
// receive path only reads the bytes that arrived).
//
// When the last reference goes, the block returns its memory to the resource and,
// if its pool caps live blocks, decrements the shared counter. It refers to
// nothing else: a Message may outlive the Connection that received it. The
// resource must outlive every block (the usual std::pmr contract).
//
// The reference count is atomic, so a Message backed by these blocks may be
// moved to another thread; the resource then has to be thread-safe.
class DataBlock {
public:
    using LiveCounter = std::atomic<std::size_t>;

    // A block of `capacity` bytes from `resource`; `live`, if not null, counts it.
    static DataBlock* create(std::pmr::memory_resource* resource, std::size_t capacity,
                             std::shared_ptr<LiveCounter> live);

    DataBlock(const DataBlock&) = delete;
    DataBlock& operator=(const DataBlock&) = delete;

    std::byte*       data()       noexcept { return storage_; }
    const std::byte* data() const noexcept { return storage_; }
    std::size_t      capacity() const noexcept { return capacity_; }

    // Where this block's memory comes from; also used for other message memory
    // derived from it (a Message's contiguous as_bytes() buffer).
    std::pmr::memory_resource* resource() const noexcept { return resource_; }

    void add_ref() noexcept {
        refcount_.fetch_add(1, std::memory_order_relaxed);
    }
    void release() noexcept {
        if (refcount_.fetch_sub(1, std::memory_order_acq_rel) == 1)
            destroy();
    }

    std::uint32_t use_count() const noexcept {
        return refcount_.load(std::memory_order_acquire);
    }

private:
    DataBlock(std::pmr::memory_resource* resource, std::byte* storage, std::size_t capacity,
              std::shared_ptr<LiveCounter> live) noexcept
        : resource_(resource), storage_(storage), capacity_(capacity), live_(std::move(live)) {}
    ~DataBlock() = default;

    void destroy() noexcept;

    std::pmr::memory_resource*   resource_;
    std::byte*                   storage_;
    std::size_t                  capacity_;
    std::atomic<std::uint32_t>   refcount_{0};
    std::shared_ptr<LiveCounter> live_;      // null when the pool has no live-block cap
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
