// Tests for MessageFramer (API v2): ReceiveCursor over a BlockChain and
// LengthPrefixedFramer::parse / write_header.

#include "taps/message_framer.h"
#include "taps/taps_api.h"

#include "buffer/block_chain.h"
#include "buffer/block_pool.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

using namespace taps;

static int g_failures = 0;

#define CHECK(cond)                                                             \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond);       \
            ++g_failures;                                                      \
        }                                                                     \
    } while (0)

// Split `bytes` into `block`-sized links of a fresh chain.
static void fill_chain(BlockChain& chain, BlockPool& pool,
                       std::span<const std::byte> bytes, std::size_t block) {
    std::size_t off = 0;
    while (off < bytes.size()) {
        BlockRef r = pool.acquire();
        CHECK(r.valid());
        const std::size_t n = std::min(block, bytes.size() - off);
        std::memcpy(r.writable_data(), bytes.data() + off, n);
        r.set_range(0, n);
        chain.append(std::move(r));
        off += n;
    }
}

static std::vector<std::byte> record(std::uint32_t len, std::uint8_t body_seed) {
    std::vector<std::byte> v;
    v.reserve(4 + len);
    v.push_back(std::byte((len >> 24) & 0xFF));
    v.push_back(std::byte((len >> 16) & 0xFF));
    v.push_back(std::byte((len >> 8) & 0xFF));
    v.push_back(std::byte(len & 0xFF));
    for (std::uint32_t i = 0; i < len; ++i)
        v.push_back(std::byte(static_cast<std::uint8_t>(body_seed + i)));
    return v;
}

static void test_cursor_copy_out_across_blocks() {
    BlockPool pool(/*block_size=*/4);
    std::vector<std::byte> data;
    for (int i = 0; i < 20; ++i) data.push_back(std::byte(static_cast<std::uint8_t>(i)));
    BlockChain chain;
    fill_chain(chain, pool, data, 4);
    CHECK(chain.block_count() == 5);

    ReceiveCursor cur(chain);
    CHECK(cur.size() == 20);

    std::byte got[7];
    cur.copy_out(3, std::span<std::byte>(got, 7));       // spans blocks 0..2
    for (int i = 0; i < 7; ++i)
        CHECK(std::to_integer<int>(got[i]) == 3 + i);
}

static void test_cursor_try_contiguous() {
    BlockPool pool(/*block_size=*/8);
    std::vector<std::byte> data(24);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = std::byte(static_cast<std::uint8_t>(i));
    BlockChain chain;
    fill_chain(chain, pool, data, 8);

    ReceiveCursor cur(chain);
    auto within = cur.try_contiguous(2, 4);              // inside block 0
    CHECK(within.has_value());
    CHECK(std::to_integer<int>((*within)[0]) == 2);
    CHECK(within->size() == 4);

    auto straddle = cur.try_contiguous(6, 4);            // block 0 -> block 1
    CHECK(!straddle.has_value());

    auto zero = cur.try_contiguous(10, 0);
    CHECK(zero.has_value());
    CHECK(zero->empty());
}

static void test_lpf_parse_need_more() {
    BlockPool pool(64);
    LengthPrefixedFramer f;  // 4-byte big-endian

    {   // empty
        BlockChain c;
        auto r = f.parse(ReceiveCursor(c), false);
        CHECK(r.action == ParseResult::Action::NeedMore);
        CHECK(r.min_bytes_needed == 4);
    }
    {   // 3 bytes: still just the prefix
        std::vector<std::byte> d{std::byte{0}, std::byte{0}, std::byte{0}};
        BlockChain c; fill_chain(c, pool, d, 64);
        auto r = f.parse(ReceiveCursor(c), false);
        CHECK(r.action == ParseResult::Action::NeedMore);
        CHECK(r.min_bytes_needed == 4);
    }
    {   // prefix says 10, only 6 body bytes present
        auto rec = record(10, 100);
        rec.resize(4 + 6);
        BlockChain c; fill_chain(c, pool, rec, 64);
        auto r = f.parse(ReceiveCursor(c), false);
        CHECK(r.action == ParseResult::Action::NeedMore);
        CHECK(r.min_bytes_needed == 14);
    }
}

static void test_lpf_parse_emit_and_second_record() {
    BlockPool pool(/*block_size=*/3);   // tiny: prefixes and bodies straddle blocks
    LengthPrefixedFramer f;

    auto r1 = record(10, 0);
    auto r2 = record(5, 200);
    std::vector<std::byte> both;
    both.insert(both.end(), r1.begin(), r1.end());
    both.insert(both.end(), r2.begin(), r2.end());

    BlockChain chain;
    fill_chain(chain, pool, both, 3);

    auto a = f.parse(ReceiveCursor(chain), false);
    CHECK(a.action == ParseResult::Action::Emit);
    CHECK(a.discard_before == 4);
    CHECK(a.deliver == 10);
    CHECK(a.end_of_message);

    // Simulate the receive loop advancing past record 1.
    chain.consume_front(a.discard_before + a.deliver);
    CHECK(chain.size() == r2.size());

    auto b = f.parse(ReceiveCursor(chain), false);
    CHECK(b.action == ParseResult::Action::Emit);
    CHECK(b.discard_before == 4);
    CHECK(b.deliver == 5);

    chain.consume_front(b.discard_before + b.deliver);
    CHECK(chain.empty());
    auto c = f.parse(ReceiveCursor(chain), true);
    CHECK(c.action == ParseResult::Action::NeedMore);
}

static void test_lpf_write_header_roundtrip() {
    LengthPrefixedFramer be(4, std::endian::big);
    LengthPrefixedFramer le(4, std::endian::little);

    Message msg(std::vector<std::uint8_t>(513));  // size() == 513 == 0x0201

    std::byte h[8];
    CHECK(be.write_header(msg, h) == 4);
    CHECK(std::to_integer<int>(h[0]) == 0x00);
    CHECK(std::to_integer<int>(h[1]) == 0x00);
    CHECK(std::to_integer<int>(h[2]) == 0x02);
    CHECK(std::to_integer<int>(h[3]) == 0x01);

    CHECK(le.write_header(msg, h) == 4);
    CHECK(std::to_integer<int>(h[0]) == 0x01);
    CHECK(std::to_integer<int>(h[1]) == 0x02);
    CHECK(std::to_integer<int>(h[2]) == 0x00);
    CHECK(std::to_integer<int>(h[3]) == 0x00);

    // header written by write_header parses back to the same length
    BlockPool pool(64);
    std::vector<std::byte> framed(h, h + 4);
    framed.resize(4 + 513);
    BlockChain c; fill_chain(c, pool, framed, 64);
    auto r = le.parse(ReceiveCursor(c), false);
    CHECK(r.action == ParseResult::Action::Emit);
    CHECK(r.deliver == 513);
}

int main() {
    test_cursor_copy_out_across_blocks();
    test_cursor_try_contiguous();
    test_lpf_parse_need_more();
    test_lpf_parse_emit_and_second_record();
    test_lpf_write_header_roundtrip();

    if (g_failures == 0) {
        std::printf("framer_test: OK\n");
        return 0;
    }
    std::printf("framer_test: %d check(s) failed\n", g_failures);
    return 1;
}
