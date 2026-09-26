#include "buffer/block_chain.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <new>

namespace taps {

BlockChain::BlockChain(const BlockChain& other) {
    for (const BlockRef& r : other)
        push_back(r);
    size_ = other.size_;
}

BlockChain::BlockChain(BlockChain&& other) noexcept {
    *this = std::move(other);
}

BlockChain& BlockChain::operator=(const BlockChain& other) {
    if (this != &other) {
        BlockChain copy(other);
        *this = std::move(copy);
    }
    return *this;
}

BlockChain& BlockChain::operator=(BlockChain&& other) noexcept {
    if (this == &other)
        return *this;
    clear();
    release_storage();
    const std::size_t size = std::exchange(other.size_, 0);
    if (other.inline_storage()) {
        for (std::size_t i = 0; i < other.count_; ++i)
            inline_[i] = std::move(other.data_[other.head_ + i]);
        count_ = other.count_;
        other.clear();
    } else {                                   // take the external storage as is
        data_ = std::exchange(other.data_, other.inline_);
        capacity_ = std::exchange(other.capacity_, kInline);
        head_ = std::exchange(other.head_, 0);
        count_ = std::exchange(other.count_, 0);
        storage_resource_ = std::exchange(other.storage_resource_, nullptr);
    }
    size_ = size;
    return *this;
}

BlockChain::~BlockChain() {
    clear();
    release_storage();
}

void BlockChain::clear() noexcept {
    for (std::size_t i = 0; i < count_; ++i)
        data_[head_ + i].reset();
    head_ = count_ = size_ = 0;
}

void BlockChain::release_storage() noexcept {
    if (inline_storage())
        return;
    for (std::size_t i = 0; i < capacity_; ++i)
        data_[i].~BlockRef();
    storage_resource_->deallocate(data_, capacity_ * sizeof(BlockRef), alignof(BlockRef));
    data_ = inline_;
    capacity_ = kInline;
    storage_resource_ = nullptr;
}

// Makes room for one more entry at the back: first by moving the live entries
// to the front, then by doubling the storage (from the blocks' resource).
void BlockChain::grow() {
    if (head_ > 0) {
        std::move(data_ + head_, data_ + head_ + count_, data_);
        head_ = 0;
        return;
    }
    std::pmr::memory_resource* const resource = data_[0].block()->resource();
    const std::size_t new_capacity = capacity_ * 2;
    auto* fresh = static_cast<BlockRef*>(
        resource->allocate(new_capacity * sizeof(BlockRef), alignof(BlockRef)));
    for (std::size_t i = 0; i < new_capacity; ++i)
        ::new (fresh + i) BlockRef();
    std::move(data_, data_ + count_, fresh);
    for (std::size_t i = 0; i < count_; ++i)
        data_[i].reset();
    release_storage();
    data_ = fresh;
    capacity_ = new_capacity;
    storage_resource_ = resource;
}

void BlockChain::push_back(BlockRef ref) {
    if (head_ + count_ == capacity_)
        grow();
    data_[head_ + count_] = std::move(ref);
    ++count_;
}

void BlockChain::append(BlockRef ref) {
    if (!ref || ref.empty())
        return;
    size_ += ref.size();
    if (count_ > 0) {
        BlockRef& last = data_[head_ + count_ - 1];
        if (last.block() == ref.block() && last.end_offset() == ref.begin_offset()) {
            last.set_range(last.begin_offset(), ref.end_offset());
            return;                            // `ref` releases its extra reference
        }
    }
    push_back(std::move(ref));
}

void BlockChain::consume_front(std::size_t n) {
    n = std::min(n, size_);
    size_ -= n;
    while (n > 0) {
        BlockRef& front = data_[head_];
        const std::size_t avail = front.size();
        if (n < avail) {
            front.advance_begin(n);
            n = 0;
        } else {
            n -= avail;
            front.reset();
            ++head_;
            --count_;
        }
    }
    if (count_ == 0)
        head_ = 0;
}

BlockChain BlockChain::first(std::size_t len) const {
    BlockChain out;
    len = std::min(len, size_);
    for (const BlockRef& r : *this) {
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
    for (const BlockRef& r : *this) {
        const std::span<const std::byte> b = r.bytes();
        std::memcpy(out.data() + off, b.data(), b.size());
        off += b.size();
    }
    return off;
}

}  // namespace taps
