#include "taps/taps_api.h"

#include "buffer/block_chain.h"

#include <cstring>
#include <memory>
#include <memory_resource>
#include <span>

namespace taps {

// Definitions that need the complete BlockChain type live here; the public header
// only forward-declares it so the block substrate stays private to src/.

std::span<const std::byte> Message::ensure_gathered() const {
    // A record that arrived wholly inside one pooled block is already contiguous:
    // view it in place (the block stays alive as long as chain_, i.e. as long as
    // this Message) instead of paying a second copy into a fresh allocation.
    // Recomputed each call — block_count() and bytes() are both O(1), no upside
    // to caching a decision this cheap.
    if (!chain_ || chain_->empty())
        return {};
    if (chain_->block_count() == 1)
        return chain_->begin()->bytes();

    if (!gathered_valid_) {
        // Message memory: from the resource the blocks came from, one allocation
        // (control block and bytes together), not zero-filled.
        const std::size_t n = chain_->size();
        gathered_ = std::allocate_shared_for_overwrite<std::byte[]>(
            std::pmr::polymorphic_allocator<std::byte>(chain_->resource()), n);
        gathered_size_ = n;
        chain_->copy_to(std::span<std::byte>(gathered_.get(), n));
        gathered_valid_ = true;
    }
    return {gathered_.get(), gathered_size_};
}

std::size_t Message::size() const noexcept {
    if (chain_)  return chain_->size();
    if (owning_) return owned_data_.size();
    return span_view_.size();
}

std::span<const std::byte> Message::as_bytes() const {
    if (chain_)  return ensure_gathered();
    if (owning_) return std::as_bytes(std::span<const std::uint8_t>(owned_data_));
    return std::as_bytes(span_view_);
}

std::size_t Message::segment_count() const noexcept {
    if (chain_)
        return chain_->block_count();
    return 1;
}

std::span<const std::byte> Message::segment(std::size_t i) const noexcept {
    if (chain_)
        return (chain_->begin() + i)->bytes();
    if (owning_)
        return std::as_bytes(std::span<const std::uint8_t>(owned_data_));
    return std::as_bytes(span_view_);
}

// Free function: gather into the caller's buffer, no internal allocation.
std::size_t gather(std::span<std::byte> out, const Message& msg) {
    if (const BlockChain* ch = msg.block_chain())
        return ch->copy_to(out.first(msg.size()));   // walk blocks, no cache touched

    const auto s = msg.as_bytes();                    // vector / span: a cheap view
    std::memcpy(out.data(), s.data(), s.size());
    return s.size();
}

}  // namespace taps
