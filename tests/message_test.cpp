// Tests for the Message backing variants after commit 2: the existing vector /
// span variants must be unchanged, and the new chain-backed variant must report
// size / endOfMessage and linearise correctly while releasing its blocks with the
// Message.

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
    if (b.size() != s.size())
        return false;
    return std::memcmp(b.data(), s.data(), s.size()) == 0;
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

static void test_vector_variant_unchanged() {
    std::vector<std::uint8_t> src{10, 20, 30, 40};
    Message m(src);
    CHECK(m.is_owning());
    CHECK(!m.is_chained());
    CHECK(m.is_end_of_message());          // classic Message is its own end
    CHECK(m.size() == 4);
    CHECK(m.length() == 4);
    CHECK(m.data().size() == 4);
    CHECK(m.data()[2] == 30);
    const auto lin = m.linearize();
    CHECK(lin.size() == 4);
    CHECK(std::to_integer<int>(lin[0]) == 10);
}

static void test_span_variant_unchanged() {
    std::vector<std::uint8_t> src{1, 2, 3, 4, 5};
    const std::span<const std::uint8_t> sp(src);
    Message m(sp);
    CHECK(!m.is_owning());
    CHECK(!m.is_chained());
    CHECK(m.is_end_of_message());
    CHECK(m.size() == 5);
    CHECK(m.view().size() == 5);
    CHECK(m.view().data() == src.data());  // still a view, no copy
    CHECK(m.linearize().data() ==
          reinterpret_cast<const std::byte*>(src.data()));
}

static void test_chain_variant_whole() {
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

    CHECK(bytes_equal(m.linearize(), s));
    CHECK(m.as_span().size() == s.size());
    CHECK(std::memcmp(m.as_span().data(), s.data(), s.size()) == 0);
    CHECK(m.data().size() == s.size());

    // Linearisation is cached: same storage on repeated calls.
    const auto first = m.linearize();
    const auto second = m.linearize();
    CHECK(first.data() == second.data());
    CHECK(m.data().data() == reinterpret_cast<const std::uint8_t*>(first.data()));
}

static void test_chain_variant_partial() {
    BlockPool pool(/*block_size=*/32);
    const std::string s = "fragment without end";
    auto chain = make_chain(pool, s, 32);

    Message m(chain, MessageContext{}, /*end_of_message=*/false);
    CHECK(m.is_chained());
    CHECK(!m.is_end_of_message());
    CHECK(m.size() == s.size());
    CHECK(bytes_equal(m.linearize(), s));
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
    test_vector_variant_unchanged();
    test_span_variant_unchanged();
    test_chain_variant_whole();
    test_chain_variant_partial();
    test_chain_blocks_released_with_message();

    if (g_failures == 0) {
        std::printf("message_test: OK\n");
        return 0;
    }
    std::printf("message_test: %d check(s) failed\n", g_failures);
    return 1;
}
