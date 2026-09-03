#include "taps/taps_api.h"

#include "buffer/block_chain.h"

#include <span>

namespace taps {

// Definitions that need the complete BlockChain type live here; the public header
// only forward-declares it so the block substrate stays private to src/.

const std::vector<std::uint8_t>& Message::ensure_linearized() const {
    if (!linearized_valid_) {
        if (chain_) {
            linearized_.resize(chain_->size());
            chain_->copy_to(std::as_writable_bytes(std::span<std::uint8_t>(linearized_)));
        }
        linearized_valid_ = true;
    }
    return linearized_;
}

std::size_t Message::size() const noexcept {
    if (chain_)  return chain_->size();
    if (owning_) return owned_data_.size();
    return span_view_.size();
}

std::span<const std::byte> Message::linearize() {
    if (chain_) {
        const std::vector<std::uint8_t>& v = ensure_linearized();
        return std::as_bytes(std::span<const std::uint8_t>(v));
    }
    if (owning_) return std::as_bytes(std::span<const std::uint8_t>(owned_data_));
    return std::as_bytes(span_view_);
}

std::span<const std::uint8_t> Message::as_span() const {
    if (chain_) {
        const std::vector<std::uint8_t>& v = ensure_linearized();
        return {v.data(), v.size()};
    }
    if (owning_) return {owned_data_.data(), owned_data_.size()};
    return span_view_;
}

const std::vector<std::uint8_t>& Message::data() const {
    if (chain_) return ensure_linearized();
    return owned_data_;
}

}  // namespace taps
