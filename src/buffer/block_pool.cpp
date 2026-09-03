#include "buffer/block_pool.h"

#include <cassert>

namespace taps {

// ----------------------------------------------------------------------------
// DataBlock::release — declared in block.h, defined here where BlockPool is complete.
// ----------------------------------------------------------------------------
void DataBlock::release() noexcept {
    if (refcount_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        if (pool_)
            pool_->recycle(this);
        else
            delete this;
    }
}

// ----------------------------------------------------------------------------
// BlockPool
// ----------------------------------------------------------------------------
BlockPool::BlockPool(std::size_t block_size, std::size_t max_free_blocks,
                     std::size_t max_live_blocks)
    : block_size_(block_size),
      max_free_blocks_(max_free_blocks),
      max_live_blocks_(max_live_blocks) {}

BlockPool::~BlockPool() {
    // A block still checked out would call recycle() on a destroyed pool.
    assert(live_count_ == 0 && "BlockPool destroyed with blocks still referenced");
    for (DataBlock* b = free_list_; b != nullptr;) {
        DataBlock* next = b->next_free_;
        delete b;
        b = next;
    }
}

BlockRef BlockPool::acquire() {
    DataBlock* blk = nullptr;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (max_live_blocks_ != 0 && live_count_ >= max_live_blocks_)
            return {};  // backpressure: caller stops reading
        if (free_list_ != nullptr) {
            blk = free_list_;
            free_list_ = blk->next_free_;
            blk->next_free_ = nullptr;
            --free_count_;
        }
        ++live_count_;
    }
    if (blk == nullptr)
        blk = new DataBlock(this, block_size_);  // deliberately outside the lock
    // refcount is 0 here; the BlockRef constructor takes it to 1.
    return BlockRef(blk, 0, 0);
}

void BlockPool::recycle(DataBlock* blk) noexcept {
    bool retained = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        --live_count_;
        if (free_count_ < max_free_blocks_) {
            blk->next_free_ = free_list_;
            free_list_ = blk;
            ++free_count_;
            retained = true;
        }
    }
    if (!retained)
        delete blk;  // outside the lock: never hold mtx_ across an allocator call
}

bool BlockPool::at_capacity() const noexcept {
    std::lock_guard<std::mutex> lk(mtx_);
    return max_live_blocks_ != 0 && live_count_ >= max_live_blocks_;
}

std::size_t BlockPool::free_blocks() const noexcept {
    std::lock_guard<std::mutex> lk(mtx_);
    return free_count_;
}

std::size_t BlockPool::live_blocks() const noexcept {
    std::lock_guard<std::mutex> lk(mtx_);
    return live_count_;
}

}  // namespace taps
