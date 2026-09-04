#include "taps/message_framer.h"

#include "taps/taps_api.h"        // taps::Message (complete type for write_header)
#include "buffer/block_chain.h"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>

namespace taps {

namespace {

// Decodes a big-/little-endian length field. Standard widths (2, 4, 8 bytes) go
// through a memcpy + std::byteswap (C++23); other widths (an unusual choice, but
// the constructor allows 1..8) fall back to the byte-at-a-time loop.
std::uint64_t decode_length(const std::byte* hdr, std::size_t field_size, std::endian order) {
    switch (field_size) {
        case 2: {
            std::uint16_t v;
            std::memcpy(&v, hdr, sizeof(v));
            if (order != std::endian::native) v = std::byteswap(v);
            return v;
        }
        case 4: {
            std::uint32_t v;
            std::memcpy(&v, hdr, sizeof(v));
            if (order != std::endian::native) v = std::byteswap(v);
            return v;
        }
        case 8: {
            std::uint64_t v;
            std::memcpy(&v, hdr, sizeof(v));
            if (order != std::endian::native) v = std::byteswap(v);
            return v;
        }
        default: {
            std::uint64_t length = 0;
            if (order == std::endian::big) {
                for (std::size_t i = 0; i < field_size; ++i)
                    length = (length << 8) | std::to_integer<std::uint64_t>(hdr[i]);
            } else {
                for (std::size_t i = 0; i < field_size; ++i)
                    length |= std::to_integer<std::uint64_t>(hdr[i]) << (i * 8);
            }
            return length;
        }
    }
}

// Inverse of decode_length: writes `length` into `out[0, field_size)`.
void encode_length(std::uint64_t length, std::byte* out, std::size_t field_size, std::endian order) {
    switch (field_size) {
        case 2: {
            auto v = static_cast<std::uint16_t>(length);
            if (order != std::endian::native) v = std::byteswap(v);
            std::memcpy(out, &v, sizeof(v));
            return;
        }
        case 4: {
            auto v = static_cast<std::uint32_t>(length);
            if (order != std::endian::native) v = std::byteswap(v);
            std::memcpy(out, &v, sizeof(v));
            return;
        }
        case 8: {
            std::uint64_t v = length;
            if (order != std::endian::native) v = std::byteswap(v);
            std::memcpy(out, &v, sizeof(v));
            return;
        }
        default: {
            if (order == std::endian::big) {
                for (std::size_t i = 0; i < field_size; ++i) {
                    const unsigned shift = static_cast<unsigned>((field_size - 1 - i) * 8);
                    out[i] = static_cast<std::byte>((length >> shift) & 0xFF);
                }
            } else {
                for (std::size_t i = 0; i < field_size; ++i)
                    out[i] = static_cast<std::byte>((length >> (i * 8)) & 0xFF);
            }
            return;
        }
    }
}

}  // namespace

// ----------------------------------------------------------------------------
// ReceiveCursor
// ----------------------------------------------------------------------------
std::size_t ReceiveCursor::size() const noexcept {
    return chain_->size();
}

void ReceiveCursor::copy_out(std::size_t off, std::span<std::byte> dst) const {
    std::size_t out = 0;
    std::size_t remaining = dst.size();
    std::size_t pos = 0;  // logical offset of the current block's first byte
    for (const BlockRef& r : *chain_) {
        const std::size_t bsz = r.size();
        if (pos + bsz <= off) {          // block entirely before the range
            pos += bsz;
            continue;
        }
        const std::size_t local = (off > pos) ? off - pos : 0;
        const std::size_t take = std::min(bsz - local, remaining);
        std::memcpy(dst.data() + out, r.bytes().data() + local, take);
        out += take;
        remaining -= take;
        pos += bsz;
        if (remaining == 0)
            return;
    }
    // Precondition (off + dst.size() <= size()) violated: leave the rest as-is.
}

std::optional<std::span<const std::byte>>
ReceiveCursor::try_contiguous(std::size_t off, std::size_t len) const noexcept {
    if (len == 0)
        return std::span<const std::byte>{};
    std::size_t pos = 0;
    for (const BlockRef& r : *chain_) {
        const std::size_t bsz = r.size();
        if (off < pos + bsz) {                    // off falls in this block
            const std::size_t local = off - pos;
            if (local + len <= bsz)
                return r.bytes().subspan(local, len);
            return std::nullopt;                  // straddles the block boundary
        }
        pos += bsz;
    }
    return std::nullopt;
}

// ----------------------------------------------------------------------------
// LengthPrefixedFramer
// ----------------------------------------------------------------------------
LengthPrefixedFramer::LengthPrefixedFramer(std::size_t length_field_size,
                                           std::endian byte_order)
    : length_field_size_(std::clamp<std::size_t>(length_field_size, 1, 8)),
      byte_order_(byte_order) {}

ParseResult LengthPrefixedFramer::parse(const ReceiveCursor& cursor, bool /*at_eof*/) {
    const std::size_t avail = cursor.size();
    if (avail < length_field_size_)
        return ParseResult::need_more(length_field_size_);

    std::byte hdr[8];
    cursor.copy_out(0, std::span<std::byte>(hdr, length_field_size_));
    const std::uint64_t length = decode_length(hdr, length_field_size_, byte_order_);

    const std::size_t total = length_field_size_ + static_cast<std::size_t>(length);
    if (avail < total)
        return ParseResult::need_more(total);

    return ParseResult::emit(static_cast<std::size_t>(length), /*eom=*/true,
                             /*discard_before=*/length_field_size_);
}

std::size_t LengthPrefixedFramer::write_header(const Message& msg,
                                               std::span<std::byte> out) {
    encode_length(msg.size(), out.data(), length_field_size_, byte_order_);
    return length_field_size_;
}

}  // namespace taps
