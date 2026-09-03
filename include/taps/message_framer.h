#pragma once

// Message Framer — API v2 (RFC 9623 Section 6): a receive-side cursor over the
// block chain plus a no-copy send-side header writer.

#include <bit>
#include <cstddef>
#include <optional>
#include <span>

namespace taps {

class Message;      // taps_api.h
class BlockChain;   // src/buffer/block_chain.h (private)

// Read-only cursor over the received-but-unparsed bytes: a logically contiguous
// view spread across the BlockChain's fixed-size blocks.
class ReceiveCursor {
public:
    explicit ReceiveCursor(const BlockChain& chain) noexcept : chain_(&chain) {}

    // Bytes available from the cursor to the end of the chain.
    std::size_t size() const noexcept;

    // Copy dst.size() bytes starting at logical offset `off` into `dst`.
    // Precondition: off + dst.size() <= size().
    void copy_out(std::size_t off, std::span<std::byte> dst) const;

    // A direct view of [off, off+len) if it lies within a single block; otherwise
    // nullopt, and the caller falls back to copy_out into its own buffer.
    // Precondition: off + len <= size().
    std::optional<std::span<const std::byte>>
        try_contiguous(std::size_t off, std::size_t len) const noexcept;

private:
    const BlockChain* chain_;
};

// Outcome of one MessageFramer::parse() call.
struct ParseResult {
    enum class Action { NeedMore, Emit };
    Action action = Action::NeedMore;

    // Action::Emit — deliver exactly one record:
    std::size_t discard_before = 0;   // framing overhead to drop before the body
    std::size_t deliver        = 0;   // body bytes delivered as one Message
    bool        end_of_message = true;

    // Action::NeedMore — hint of the total cursor size parse() needs before it can
    // make progress (0 = unknown).
    std::size_t min_bytes_needed = 0;

    static ParseResult need_more(std::size_t hint = 0) noexcept {
        return {Action::NeedMore, 0, 0, true, hint};
    }
    static ParseResult emit(std::size_t deliver, bool eom = true,
                            std::size_t discard_before = 0) noexcept {
        return {Action::Emit, discard_before, deliver, eom, 0};
    }
};

// One MessageFramer instance per Connection. parse() is called repeatedly on the
// receive cursor; write_header() once per sent Message.
class MessageFramer {
public:
    virtual ~MessageFramer() = default;

    // Inspect the cursor and decide. `at_eof` becomes true once the peer has
    // half-closed. Returns Emit for exactly one record (the receive loop calls
    // parse() again after the cursor advances) or NeedMore to read more.
    virtual ParseResult parse(const ReceiveCursor& cursor, bool at_eof) = 0;

    // Write the framing header for `msg` into `out` (sized >= max_header_size()).
    // Returns the number of bytes written; 0 if the framer adds no header. The
    // payload is never copied — the caller gather-writes header + payload.
    virtual std::size_t write_header(const Message& msg, std::span<std::byte> out) = 0;

    // Upper bound on write_header()'s output, so the caller can stack-allocate.
    virtual std::size_t max_header_size() const noexcept = 0;
};

// Length-prefixed records: an integer of `length_field_size` bytes (1..8, big- or
// little-endian) giving the body length, followed by the body. Each record is one
// Message with end_of_message == true.
class LengthPrefixedFramer : public MessageFramer {
public:
    explicit LengthPrefixedFramer(std::size_t length_field_size = 4,
                                  std::endian byte_order = std::endian::big);

    ParseResult parse(const ReceiveCursor& cursor, bool at_eof) override;
    std::size_t write_header(const Message& msg, std::span<std::byte> out) override;
    std::size_t max_header_size() const noexcept override { return length_field_size_; }

private:
    std::size_t length_field_size_;
    std::endian byte_order_;
};

}  // namespace taps
