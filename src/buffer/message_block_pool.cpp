#include "buffer/message_block_pool.h"

#include "taps/taps_api.h"   // MessageMemoryConfig, default_message_resource()

#include <new>

namespace taps {

DataBlock* DataBlock::create(std::pmr::memory_resource* resource, std::size_t capacity,
                             std::shared_ptr<LiveCounter> live) {
    auto* storage = static_cast<std::byte*>(resource->allocate(capacity, alignof(std::max_align_t)));
    void* header = nullptr;
    try {
        header = resource->allocate(sizeof(DataBlock), alignof(DataBlock));
    } catch (...) {
        resource->deallocate(storage, capacity, alignof(std::max_align_t));
        throw;
    }
    return ::new (header) DataBlock(resource, storage, capacity, std::move(live));
}

void DataBlock::destroy() noexcept {
    std::pmr::memory_resource* const resource = resource_;
    std::byte* const storage = storage_;
    const std::size_t capacity = capacity_;
    if (live_)
        live_->fetch_sub(1, std::memory_order_relaxed);
    this->~DataBlock();
    resource->deallocate(storage, capacity, alignof(std::max_align_t));
    resource->deallocate(this, sizeof(DataBlock), alignof(DataBlock));
}

MessageBlockPool::MessageBlockPool(const MessageMemoryConfig& config)
    : resource_(config.resource ? config.resource : default_message_resource()),
      block_size_(config.block_size),
      max_live_blocks_(config.max_live_blocks) {
    if (max_live_blocks_ != 0)
        live_ = std::allocate_shared<DataBlock::LiveCounter>(
            std::pmr::polymorphic_allocator<DataBlock::LiveCounter>(resource_), 0u);
}

BlockRef MessageBlockPool::acquire() {
    if (live_) {
        // Reserve a slot first; give it back if the cap was already reached.
        if (live_->fetch_add(1, std::memory_order_relaxed) >= max_live_blocks_) {
            live_->fetch_sub(1, std::memory_order_relaxed);
            return {};
        }
    }
    DataBlock* blk = nullptr;
    try {
        blk = DataBlock::create(resource_, block_size_, live_);
    } catch (...) {
        if (live_)
            live_->fetch_sub(1, std::memory_order_relaxed);
        throw;
    }
    return BlockRef(blk, 0, 0);   // refcount 0 -> 1
}

bool MessageBlockPool::at_capacity() const noexcept {
    return live_ && live_->load(std::memory_order_relaxed) >= max_live_blocks_;
}

std::size_t MessageBlockPool::live_blocks() const noexcept {
    return live_ ? live_->load(std::memory_order_relaxed) : 0;
}

}  // namespace taps
