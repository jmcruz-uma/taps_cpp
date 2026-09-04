// Tests for the Message byte-access API: the vector / span variants stay cheap,
// the chain-backed variant reports size / endOfMessage, exposes its blocks with
// zero copy, assembles contiguously on demand via as_bytes(), and copies into a
// caller buffer via taps::gather(). Blocks are released with the Message.

#include "taps/taps_api.h"

#include "buffer/block_chain.h"
#include "buffer/block_pool.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
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

static bool bytes_equal(std::span<const std::byte> b, const std::string& s) {
    return b.size() == s.size() && std::memcmp(b.data(), s.data(), s.size()) == 0;
}

// Builds a chain holding a copy of `s` split into `block`-sized links.
static std::shared_ptr<BlockChain> make_chain(BlockPool& pool, const std::string& s,
                                              std::size_t block) {
    auto chain = std::make_shared<BlockChain>();
    std::size_t off = 0;
    while (off < s.size()) {
        BlockRef r = pool.acquire();
        CHECK(r.valid());
        const std::size_t n = std::min(block, s.size() - off);
        std::memcpy(r.writable_data(), s.data() + off, n);
        r.set_range(0, n);
        chain->append(std::move(r));
        off += n;
    }
    return chain;
}

static void test_vector_variant() {
    std::vector<std::uint8_t> src{10, 20, 30, 40};
    Message m(src);
    CHECK(m.is_owning());
    CHECK(!m.is_chained());
    CHECK(m.is_end_of_message());          // classic Message is its own end
    CHECK(m.size() == 4);
    CHECK(m.length() == 4);

    const auto b = m.as_bytes();
    CHECK(b.size() == 4);
    CHECK(std::to_integer<int>(b[2]) == 30);

    const auto segs = m.blocks();
    CHECK(segs.size() == 1);              // contiguous -> a single segment
    CHECK(segs[0].size() == 4);
}

static void test_span_variant() {
    std::vector<std::uint8_t> src{1, 2, 3, 4, 5};
    const std::span<const std::uint8_t> sp(src);
    Message m(sp);
    CHECK(!m.is_owning());
    CHECK(!m.is_chained());
    CHECK(m.is_end_of_message());
    CHECK(m.size() == 5);

    // as_bytes() on the span variant is a view over the caller's data, no copy.
    CHECK(m.as_bytes().data() == reinterpret_cast<const std::byte*>(src.data()));
    CHECK(m.blocks().size() == 1);
    CHECK(m.blocks()[0].data() == reinterpret_cast<const std::byte*>(src.data()));
}

static void test_chain_as_bytes() {
    BlockPool pool(/*block_size=*/16);
    const std::string s = "the quick brown fox jumps over the lazy dog, twice.";
    auto chain = make_chain(pool, s, 16);
    CHECK(chain->block_count() >= 3);

    Message m(chain);                      // default end_of_message = true
    CHECK(m.is_chained());
    CHECK(!m.is_owning());
    CHECK(m.is_end_of_message());
    CHECK(m.size() == s.size());
    CHECK(m.length() == s.size());

    CHECK(bytes_equal(m.as_bytes(), s));

    // as_bytes() caches: same storage on repeated calls.
    CHECK(m.as_bytes().data() == m.as_bytes().data());
}

static void test_chain_blocks_zero_copy() {
    BlockPool pool(/*block_size=*/16);
    const std::string s(70, '\0');
    std::string filled = s;
    for (std::size_t i = 0; i < filled.size(); ++i)
        filled[i] = static_cast<char>(i);
    auto chain = make_chain(pool, filled, 16);

    Message m(chain);
    const auto segs = m.blocks();
    CHECK(segs.size() == chain->block_count());     // one segment per block
    CHECK(segs.size() == 5);                        // 70 / 16 -> 4x16 + 6

    // Segments point straight into the pooled blocks (no copy) and concatenate
    // back to the original stream.
    std::size_t off = 0;
    for (const auto seg : segs) {
        CHECK(std::memcmp(seg.data(), filled.data() + off, seg.size()) == 0);
        off += seg.size();
    }
    CHECK(off == filled.size());
}

static void test_free_copy() {
    BlockPool pool(/*block_size=*/8);
    const std::string s = "assemble me into a caller buffer";
    auto chain = make_chain(pool, s, 8);
    Message chained(chain);

    std::vector<std::byte> out(chained.size());
    const std::size_t n = taps::gather(out, chained);
    CHECK(n == s.size());
    CHECK(bytes_equal(out, s));

    // Same free function on a vector-backed Message.
    std::vector<std::uint8_t> src(s.begin(), s.end());
    Message owned(src);
    std::vector<std::byte> out2(owned.size());
    CHECK(taps::gather(out2, owned) == s.size());
    CHECK(bytes_equal(out2, s));
}

static void test_chain_partial() {
    BlockPool pool(/*block_size=*/32);
    const std::string s = "fragment without end";
    auto chain = make_chain(pool, s, 32);

    Message m(chain, MessageContext{}, /*end_of_message=*/false);
    CHECK(m.is_chained());
    CHECK(!m.is_end_of_message());
    CHECK(m.size() == s.size());
    CHECK(bytes_equal(m.as_bytes(), s));
}

static void test_chain_blocks_released_with_message() {
    BlockPool pool(/*block_size=*/16);
    const std::string s(200, 'x');
    CHECK(pool.live_blocks() == 0);
    {
        auto chain = make_chain(pool, s, 16);
        const std::size_t n = pool.live_blocks();
        CHECK(n >= 13);
        {
            Message m(chain);
            CHECK(pool.live_blocks() == n);   // shared, not copied
            CHECK(m.size() == s.size());
        }
        CHECK(pool.live_blocks() == n);       // local `chain` still holds it
    }
    CHECK(pool.live_blocks() == 0);           // both references gone
}

int main() {
    test_vector_variant();
    test_span_variant();
    test_chain_as_bytes();
    test_chain_blocks_zero_copy();
    test_free_copy();
    test_chain_partial();
    test_chain_blocks_released_with_message();

    if (g_failures == 0) {
        std::printf("message_test: OK\n");
        return 0;
    }
    std::printf("message_test: %d check(s) failed\n", g_failures);
    return 1;
}
