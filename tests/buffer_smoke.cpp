// Smoke test for the block-chain receive substrate: MessageBlockPool / DataBlock /
// BlockRef / BlockChain, in isolation. Message memory comes from a counting
// std::pmr resource, so the tests can see every allocation and its release.

#include "buffer/block_chain.h"
#include "buffer/message_block_pool.h"
#include "taps/taps_api.h"
#include "taps/mailbox.h"

#include <asio/io_context.hpp>
#include <deque>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <memory_resource>
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

// Forwards to an upstream resource and counts calls and outstanding allocations.
struct CountingResource final : std::pmr::memory_resource {
    explicit CountingResource(std::pmr::memory_resource* up = std::pmr::new_delete_resource())
        : upstream(up) {}
    std::pmr::memory_resource* upstream;
    std::size_t allocations = 0, deallocations = 0, largest = 0;
    std::size_t outstanding() const { return allocations - deallocations; }

    void* do_allocate(std::size_t n, std::size_t a) override {
        ++allocations;
        if (n > largest) largest = n;
        return upstream->allocate(n, a);
    }
    void do_deallocate(void* p, std::size_t n, std::size_t a) override {
        ++deallocations;
        upstream->deallocate(p, n, a);
    }
    bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override { return this == &o; }
};

static MessageMemoryConfig config(std::pmr::memory_resource* r, std::size_t block_size,
                                  std::size_t max_live_blocks = 0) {
    MessageMemoryConfig c;
    c.resource = r;
    c.block_size = block_size;
    c.max_live_blocks = max_live_blocks;
    return c;
}

// A cap far above what any test uses, so live_blocks() reports the count.
constexpr std::size_t kCounted = 1000;

// Fills a fresh block from `pool` with `n` bytes of a recognisable pattern and
// returns it as a BlockRef whose live window is [0, n).
static BlockRef make_filled(MessageBlockPool& pool, std::size_t n, std::uint8_t seed) {
    BlockRef ref = pool.acquire();
    CHECK(ref.valid());
    std::byte* p = ref.writable_data();
    for (std::size_t i = 0; i < n; ++i)
        p[i] = static_cast<std::byte>(static_cast<std::uint8_t>(seed + i));
    ref.set_range(0, n);
    return ref;
}

// A block is two allocations from the resource (header and payload, the payload
// exactly block_size), both returned when the last reference goes.
static void test_pool_acquire_release() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 4096));
    CHECK(pool.block_size() == 4096);
    CHECK(pool.resource() == &res);
    {
        BlockRef a = pool.acquire();
        CHECK(a.valid());
        CHECK(a.empty());                       // window starts at [0, 0)
        CHECK(a.capacity_after_begin() == 4096);
        CHECK(a.block()->use_count() == 1);
        CHECK(res.outstanding() == 2);
        CHECK(res.largest == 4096);
    }
    CHECK(res.outstanding() == 0);
}

// Recycling is the resource's: over a pool resource, a released block's memory is
// reused without going back upstream.
static void test_recycling_by_pool_resource() {
    CountingResource upstream;
    std::pmr::unsynchronized_pool_resource pooled(message_pool_options(), &upstream);
    MessageBlockPool pool(config(&pooled, 4096));
    { BlockRef warm = pool.acquire(); }
    const std::size_t after_warm = upstream.allocations;
    for (int i = 0; i < 10; ++i) {
        BlockRef b = pool.acquire();
        CHECK(b.valid());
    }
    CHECK(upstream.allocations == after_warm);
}

static void test_blockref_shared_ownership() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 4096, kCounted));
    BlockRef a = pool.acquire();
    CHECK(a.block()->use_count() == 1);
    {
        BlockRef b = a;                         // copy -> +1 ref, same block
        CHECK(b.block() == a.block());
        CHECK(a.block()->use_count() == 2);
        CHECK(pool.live_blocks() == 1);         // still one block in flight
    }
    CHECK(a.block()->use_count() == 1);
    a.reset();
    CHECK(pool.live_blocks() == 0);
    CHECK(res.outstanding() == 1);              // only the shared cap counter remains
}

static void test_live_cap_backpressure() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 1024, /*max_live_blocks=*/3));
    BlockRef r0 = pool.acquire();
    BlockRef r1 = pool.acquire();
    BlockRef r2 = pool.acquire();
    CHECK(r0.valid() && r1.valid() && r2.valid());
    CHECK(pool.at_capacity());

    BlockRef denied = pool.acquire();
    CHECK(!denied.valid());                     // backpressure signal
    CHECK(pool.live_blocks() == 3);

    r1.reset();                                 // free one slot
    CHECK(!pool.at_capacity());
    BlockRef r3 = pool.acquire();
    CHECK(r3.valid());
    CHECK(pool.live_blocks() == 3);
}

// A block may outlive the pool that handed it out (a received Message kept after
// its Connection is gone): it refers only to the resource and the shared counter.
static void test_block_outlives_pool() {
    CountingResource res;
    BlockRef kept;
    {
        MessageBlockPool pool(config(&res, 1024, /*max_live_blocks=*/2));
        kept = pool.acquire();
        kept.writable_data()[0] = std::byte{42};
        kept.set_range(0, 1);
    }
    CHECK(kept.valid() && kept.bytes()[0] == std::byte{42});
    kept.reset();
    CHECK(res.outstanding() == 0);
}

static void test_chain_append_and_linearize() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 64, kCounted));
    BlockChain chain;
    CHECK(chain.empty());

    chain.append(make_filled(pool, 64, 0));     // bytes 0..63
    chain.append(make_filled(pool, 64, 64));    // "bytes" 64..127 (wraps in uint8)
    chain.append(make_filled(pool, 10, 200));

    CHECK(chain.block_count() == 3);
    CHECK(chain.size() == 138);
    CHECK(pool.live_blocks() == 3);

    std::vector<std::byte> out(chain.size());
    CHECK(chain.copy_to(out) == 138);
    for (std::size_t i = 0; i < 64; ++i)
        CHECK(out[i] == static_cast<std::byte>(static_cast<std::uint8_t>(i)));
    for (std::size_t i = 0; i < 64; ++i)
        CHECK(out[64 + i] == static_cast<std::byte>(static_cast<std::uint8_t>(64 + i)));
    for (std::size_t i = 0; i < 10; ++i)
        CHECK(out[128 + i] == static_cast<std::byte>(static_cast<std::uint8_t>(200 + i)));
}

static void test_chain_consume_front() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 64, kCounted));
    BlockChain chain;
    chain.append(make_filled(pool, 64, 0));
    chain.append(make_filled(pool, 64, 64));
    chain.append(make_filled(pool, 64, 128));
    CHECK(pool.live_blocks() == 3);

    // Consume less than the first block: nothing released, bytes shift.
    chain.consume_front(10);
    CHECK(chain.size() == 182);
    CHECK(chain.block_count() == 3);
    CHECK(pool.live_blocks() == 3);

    // Consume across a boundary: first block fully gone, second straddled.
    chain.consume_front(100);                   // 10 + 100 = 110 consumed total
    CHECK(chain.size() == 82);
    CHECK(chain.block_count() == 2);
    CHECK(pool.live_blocks() == 2);

    // Remaining bytes must be the original stream offset 110 onward.
    std::vector<std::byte> out(chain.size());
    chain.copy_to(out);
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::uint8_t expected =
            (110 + i < 128) ? static_cast<std::uint8_t>(64 + (110 + i - 64))
                            : static_cast<std::uint8_t>(128 + (110 + i - 128));
        CHECK(out[i] == static_cast<std::byte>(expected));
    }

    // Consume the rest: chain empty, every block released.
    chain.consume_front(1000);
    CHECK(chain.empty());
    CHECK(chain.block_count() == 0);
    CHECK(pool.live_blocks() == 0);
}

static void test_chain_first_slice() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 16, kCounted));
    BlockChain chain;
    chain.append(make_filled(pool, 16, 0));      // stream [0,16)
    chain.append(make_filled(pool, 16, 16));     // stream [16,32)
    chain.append(make_filled(pool, 16, 32));     // stream [32,48)
    CHECK(pool.live_blocks() == 3);

    // A slice straddling the second block: shares blocks, does not consume.
    BlockChain slice = chain.first(24);
    CHECK(slice.size() == 24);
    CHECK(chain.size() == 48);                   // source untouched
    CHECK(slice.block_count() == 2);             // full block 0 + 8 bytes of block 1
    CHECK(pool.live_blocks() == 3);              // shared, no new blocks

    std::vector<std::byte> out(24);
    slice.copy_to(out);
    for (std::size_t i = 0; i < 24; ++i)
        CHECK(out[i] == static_cast<std::byte>(static_cast<std::uint8_t>(i)));

    // Now consume the same 24 bytes from the source; block 0 is released by the
    // source but stays live because the slice still references it.
    chain.consume_front(24);
    CHECK(chain.size() == 24);
    CHECK(pool.live_blocks() == 3);

    // Dropping the slice releases block 0 (its only remaining ref).
    slice = BlockChain{};
    CHECK(pool.live_blocks() == 2);

    // first() clamps to size().
    BlockChain all = chain.first(1000);
    CHECK(all.size() == 24);
}

// Up to two entries live inside the chain: no allocation beyond the blocks.
static void test_chain_inline_entries() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 64));
    BlockChain chain;
    chain.append(make_filled(pool, 64, 0));
    chain.append(make_filled(pool, 64, 64));
    CHECK(chain.block_count() == 2);
    CHECK(res.outstanding() == 4);              // two blocks, header + payload each
}

// A ref that continues the last one in the same block extends it; any other ref
// is a new entry.
static void test_chain_merges_contiguous_refs() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 64));
    BlockRef block = pool.acquire();
    for (std::size_t i = 0; i < 30; ++i)
        block.writable_data()[i] = static_cast<std::byte>(i);
    BlockChain chain;
    BlockRef a = block; a.set_range(0, 10);
    BlockRef b = block; b.set_range(10, 25);
    BlockRef c = block; c.set_range(26, 30);     // gap: not contiguous with b
    chain.append(a);
    chain.append(b);
    CHECK(chain.block_count() == 1 && chain.size() == 25);
    chain.append(c);
    CHECK(chain.block_count() == 2 && chain.size() == 29);
    std::vector<std::byte> out(chain.size());
    chain.copy_to(out);
    for (std::size_t i = 0; i < 25; ++i)
        CHECK(out[i] == static_cast<std::byte>(i));
    for (std::size_t i = 0; i < 4; ++i)
        CHECK(out[25 + i] == static_cast<std::byte>(26 + i));
}

// Beyond two entries the storage comes from the blocks' resource and goes back
// to it; copies and moves keep the bytes and the ownership right.
static void test_chain_overflow_copy_move() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 16));
    {
        BlockChain chain;
        for (std::uint8_t i = 0; i < 5; ++i)
            chain.append(make_filled(pool, 16, static_cast<std::uint8_t>(i * 16)));
        CHECK(chain.block_count() == 5 && chain.size() == 80);
        CHECK(res.outstanding() == 5 * 2 + 1);   // blocks + one entry array

        BlockChain copy = chain;                  // shares blocks, own entry array
        CHECK(copy.size() == 80 && copy.block_count() == 5);
        CHECK(res.outstanding() == 5 * 2 + 2);
        BlockChain moved = std::move(chain);      // takes the array
        CHECK(moved.size() == 80 && chain.size() == 0 && chain.block_count() == 0);
        CHECK(res.outstanding() == 5 * 2 + 2);

        std::vector<std::byte> a(80), b(80);
        copy.copy_to(a);
        moved.copy_to(b);
        CHECK(a == b);
        for (std::size_t i = 0; i < 80; ++i)
            CHECK(a[i] == static_cast<std::byte>(static_cast<std::uint8_t>(i)));

        BlockChain small;                         // inline move
        small.append(make_filled(pool, 16, 0));
        BlockChain small_moved = std::move(small);
        CHECK(small_moved.size() == 16 && small_moved.block_count() == 1 && small.empty());
    }
    CHECK(res.outstanding() == 0);
}

// A chain held by a Message comes from the resource.
static void test_make_chain_from_resource() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 16));
    {
        auto chain = make_chain(&res);
        CHECK(res.outstanding() == 1);
        chain->append(make_filled(pool, 16, 0));
        CHECK(res.outstanding() == 3);
    }
    CHECK(res.outstanding() == 0);
}

// The receive chain's pattern — appends of varying size, sometimes continuing a
// block, consumes and slices interleaved — against a byte-for-byte model.
static void test_chain_against_model() {
    CountingResource res;
    MessageBlockPool pool(config(&res, 32));
    BlockChain chain;
    std::vector<std::uint8_t> model;             // the bytes the chain must hold
    std::uint32_t rng = 12345;
    auto next = [&rng] { rng = rng * 1103515245u + 12345u; return (rng >> 16) & 0x7fffu; };
    std::uint8_t counter = 0;
    BlockRef current = pool.acquire();
    std::size_t used = 0;
    for (int step = 0; step < 5000; ++step) {
        const unsigned op = next() % 4;
        if (op <= 1) {                            // append 1..20 bytes, continuing the block if it fits
            std::size_t n = 1 + next() % 20;
            if (used + n > 32) { current = pool.acquire(); used = 0; }
            n = std::min<std::size_t>(n, 32 - used);
            for (std::size_t i = 0; i < n; ++i) {
                current.block()->data()[used + i] = static_cast<std::byte>(counter);
                model.push_back(counter++);
            }
            BlockRef piece(current.block(), used, used + n);
            used += n;
            chain.append(std::move(piece));
        } else if (op == 2) {                     // consume a few bytes
            const std::size_t n = std::min<std::size_t>(next() % 25, model.size());
            chain.consume_front(n);
            model.erase(model.begin(), model.begin() + static_cast<std::ptrdiff_t>(n));
        } else {                                  // slice and compare
            const std::size_t n = std::min<std::size_t>(next() % 40, model.size());
            const BlockChain slice = chain.first(n);
            std::vector<std::byte> out(slice.size());
            slice.copy_to(out);
            bool same = slice.size() == n;
            for (std::size_t i = 0; same && i < n; ++i)
                same = out[i] == static_cast<std::byte>(model[i]);
            CHECK(same);
        }
        CHECK(chain.size() == model.size());
    }
    std::vector<std::byte> out(chain.size());
    chain.copy_to(out);
    bool same = true;
    for (std::size_t i = 0; same && i < model.size(); ++i)
        same = out[i] == static_cast<std::byte>(model[i]);
    CHECK(same);
    current.reset();
    chain = BlockChain{};
    CHECK(res.outstanding() == 0);
}

// The Mailbox ring against a model: deliveries and pops interleaved at random, with
// growth from empty and drop-oldest at the bound; order, drop count and storage
// returned to the resource.
static void test_mailbox_against_model() {
    CountingResource res;
    {
        asio::io_context io;
        constexpr std::size_t kBound = 64;          // growth 4 → 8 → 16 → 32 → 64
        Mailbox mailbox(io.get_executor(), &res, kBound);
        std::deque<const BlockChain*> model;
        std::vector<std::shared_ptr<BlockChain>> tags(20000);
        std::size_t next = 0, dropped = 0;
        std::uint32_t rng = 777;
        auto rand = [&rng] { rng = rng * 1103515245u + 12345u; return (rng >> 16) & 0x7fffu; };
        bool same = true;
        for (int step = 0; step < 20000 && next < tags.size(); ++step) {
            if (rand() % 3 != 0) {                    // deliver (twice as likely as pop)
                tags[next] = std::make_shared<BlockChain>();
                mailbox.deliver(tags[next]);
                if (model.size() == kBound) { model.pop_front(); ++dropped; }
                model.push_back(tags[next].get());
                ++next;
            } else {
                auto d = mailbox.try_pop();
                const BlockChain* want = model.empty() ? nullptr : model.front();
                if (!model.empty()) model.pop_front();
                same = same && d.get() == want;
            }
        }
        CHECK(same);
        CHECK(mailbox.dropped() == dropped);
        while (!model.empty()) {
            same = same && mailbox.try_pop().get() == model.front();
            model.pop_front();
        }
        CHECK(same && !mailbox.try_pop());
    }
    CHECK(res.outstanding() == 0);
}

int main() {
    test_pool_acquire_release();
    test_recycling_by_pool_resource();
    test_blockref_shared_ownership();
    test_live_cap_backpressure();
    test_block_outlives_pool();
    test_chain_append_and_linearize();
    test_chain_consume_front();
    test_chain_first_slice();
    test_chain_inline_entries();
    test_chain_merges_contiguous_refs();
    test_chain_overflow_copy_move();
    test_make_chain_from_resource();
    test_chain_against_model();
    test_mailbox_against_model();

    if (g_failures == 0) {
        std::printf("buffer_smoke: OK\n");
        return 0;
    }
    std::printf("buffer_smoke: %d check(s) failed\n", g_failures);
    return 1;
}
