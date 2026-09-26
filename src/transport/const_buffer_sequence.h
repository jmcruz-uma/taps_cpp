#pragma once

#include "buffer/block_chain.h"
#include "taps/taps_api.h"   // Message

#include <asio/buffer.hpp>

#include <cstddef>
#include <iterator>
#include <span>

namespace taps {

// What one send() puts on the wire: an optional framing header, then either a
// contiguous body or the blocks of a chain. A forward range of asio::const_buffer
// (an asio ConstBufferSequence), so a write consumes it directly: no array of
// buffers is built and no byte is copied. The header, the body and the chain must
// stay alive and unchanged until the write completes.
class ConstBufferSequence {
public:
    ConstBufferSequence(std::span<const std::byte> header, std::span<const std::byte> body) noexcept
        : header_(header), body_(body) {}
    ConstBufferSequence(std::span<const std::byte> header, const BlockChain& chain) noexcept
        : header_(header), chain_(&chain) {}
    // A Message as it is: its blocks if it was received, its one segment otherwise.
    ConstBufferSequence(std::span<const std::byte> header, const Message& message) noexcept
        : header_(header), chain_(message.block_chain()) {
        if (!chain_)
            body_ = *message.blocks().begin();
    }

    class const_iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = asio::const_buffer;
        using difference_type   = std::ptrdiff_t;
        using pointer           = void;
        using reference         = asio::const_buffer;

        const_iterator() noexcept = default;

        asio::const_buffer operator*() const noexcept {
            if (stage_ == Stage::header) return asio::buffer(seq_->header_.data(), seq_->header_.size());
            if (stage_ == Stage::body)   return asio::buffer(seq_->body_.data(), seq_->body_.size());
            return asio::buffer(ref_->data(), ref_->size());
        }
        const_iterator& operator++() noexcept {
            if (stage_ == Stage::chain) ++ref_;
            else stage_ = static_cast<Stage>(static_cast<int>(stage_) + 1);
            skip_empty();
            return *this;
        }
        const_iterator operator++(int) noexcept { const_iterator old = *this; ++*this; return old; }
        bool operator==(const const_iterator& o) const noexcept {
            return stage_ == o.stage_ && (stage_ != Stage::chain || ref_ == o.ref_);
        }

    private:
        friend class ConstBufferSequence;
        enum class Stage { header, body, chain, end };

        const_iterator(const ConstBufferSequence* seq, Stage stage) noexcept
            : seq_(seq), stage_(stage) { skip_empty(); }

        // Moves past empty parts, so every buffer the iterator yields has bytes.
        void skip_empty() noexcept {
            if (stage_ == Stage::header && seq_->header_.empty())
                stage_ = Stage::body;
            if (stage_ == Stage::body && (seq_->chain_ || seq_->body_.empty())) {
                stage_ = Stage::chain;
                ref_ = seq_->chain_ ? seq_->chain_->begin() : nullptr;
            }
            if (stage_ == Stage::chain && (!seq_->chain_ || ref_ == seq_->chain_->end()))
                stage_ = Stage::end;
        }

        const ConstBufferSequence* seq_ = nullptr;
        Stage                      stage_ = Stage::end;
        const BlockRef*            ref_ = nullptr;
    };

    const_iterator begin() const noexcept { return {this, const_iterator::Stage::header}; }
    const_iterator end()   const noexcept { return {this, const_iterator::Stage::end}; }

private:
    std::span<const std::byte> header_;
    std::span<const std::byte> body_;
    const BlockChain*          chain_ = nullptr;
};

}  // namespace taps
