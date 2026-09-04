#include "taps/taps_api.h"

#include "buffer/block_chain.h"

#include <cstring>
#include <memory>
#include <span>

namespace taps {

// Definitions that need the complete BlockChain type live here; the public header
// only forward-declares it so the block substrate stays private to src/.

std::span<const std::byte> Message::ensure_gathered() const {
    if (!gathered_valid_) {
        const std::size_t n = chain_ ? chain_->size() : 0;
        // new[] (not make_shared) leaves the bytes uninitialised — we overwrite
        // all of them immediately; no wasted zero-fill.
        gathered_ = std::shared_ptr<std::byte[]>(new std::byte[n]);
        gathered_size_ = n;
        if (chain_ && n)
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

std::vector<std::span<const std::byte>> Message::blocks() const {
    std::vector<std::span<const std::byte>> out;
    if (chain_) {
        out.reserve(chain_->block_count());
        for (const BlockRef& b : *chain_)
            out.push_back(b.bytes());
        return out;
    }
    if (owning_)
        out.push_back(std::as_bytes(std::span<const std::uint8_t>(owned_data_)));
    else
        out.push_back(std::as_bytes(span_view_));
    return out;
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
