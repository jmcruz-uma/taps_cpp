// Smoke test for the block-chain receive substrate: BlockPool / DataBlock /
// BlockRef / BlockChain. This exercises the substrate in isolation; it is not yet
// wired into the TAPS receive path (that is a later commit).

#include "buffer/block_chain.h"
#include "buffer/block_pool.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
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

// Fills a fresh block from `pool` with `n` bytes of a recognisable pattern and
// returns it as a BlockRef whose live window is [0, n).
static BlockRef make_filled(BlockPool& pool, std::size_t n, std::uint8_t seed) {
    BlockRef ref = pool.acquire();
    CHECK(ref.valid());
    std::byte* p = ref.writable_data();
    for (std::size_t i = 0; i < n; ++i)
        p[i] = static_cast<std::byte>(static_cast<std::uint8_t>(seed + i));
    ref.set_range(0, n);
    return ref;
}

static void test_pool_acquire_release() {
    BlockPool pool(/*block_size=*/4096);
    CHECK(pool.block_size() == 4096);
    CHECK(pool.live_blocks() == 0);
    CHECK(pool.free_blocks() == 0);

    {
        BlockRef a = pool.acquire();
        CHECK(a.valid());
        CHECK(a.empty());                       // window starts at [0, 0)
        CHECK(a.capacity_after_begin() == 4096);
        CHECK(pool.live_blocks() == 1);
        CHECK(a.block()->use_count() == 1);
    }
    CHECK(pool.live_blocks() == 0);
    CHECK(pool.free_blocks() == 1);             // recycled, not freed
}

static void test_pool_recycles_same_storage() {
    BlockPool pool(4096);
    DataBlock* first = nullptr;
    {
        BlockRef a = pool.acquire();
        first = a.block();
    }
    CHECK(pool.free_blocks() == 1);
    {
        BlockRef b = pool.acquire();
        CHECK(b.block() == first);              // pulled off the free list
        CHECK(pool.free_blocks() == 0);
        CHECK(pool.live_blocks() == 1);
    }
}

static void test_blockref_shared_ownership() {
    BlockPool pool(4096);
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
    CHECK(pool.free_blocks() == 1);
}

static void test_free_list_cap() {
    BlockPool pool(/*block_size=*/1024, /*max_free_blocks=*/2);
    {
        BlockRef r0 = pool.acquire();
        BlockRef r1 = pool.acquire();
        BlockRef r2 = pool.acquire();
        BlockRef r3 = pool.acquire();
        CHECK(pool.live_blocks() == 4);
    }
    // Four released, only two retained; the other two were freed.
    CHECK(pool.live_blocks() == 0);
    CHECK(pool.free_blocks() == 2);
}

static void test_live_cap_backpressure() {
    BlockPool pool(/*block_size=*/1024, /*max_free_blocks=*/8, /*max_live_blocks=*/3);
    BlockRef r0 = pool.acquire();
    BlockRef r1 = pool.acquire();
    BlockRef r2 = pool.acquire();
    CHECK(r0.valid() && r1.valid() && r2.valid());
    CHECK(pool.at_capacity());

    BlockRef denied = pool.acquire();
    CHECK(!denied.valid());                     // backpressure signal

    r1.reset();                                 // free one slot
    CHECK(!pool.at_capacity());
    BlockRef r3 = pool.acquire();
    CHECK(r3.valid());
    CHECK(pool.live_blocks() == 3);
}

static void test_chain_append_and_linearize() {
    BlockPool pool(/*block_size=*/64);
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
    BlockPool pool(/*block_size=*/64, /*max_free_blocks=*/8);
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
    CHECK(pool.free_blocks() == 1);

    // Remaining bytes must be the original stream offset 110 onward.
    std::vector<std::byte> out(chain.size());
    chain.copy_to(out);
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::uint8_t expected =
            (110 + i < 128) ? static_cast<std::uint8_t>(64 + (110 + i - 64))
                            : static_cast<std::uint8_t>(128 + (110 + i - 128));
        CHECK(out[i] == static_cast<std::byte>(expected));
    }

    // Consume the rest: chain empty, everything back in the pool.
    chain.consume_front(1000);
    CHECK(chain.empty());
    CHECK(chain.block_count() == 0);
    CHECK(pool.live_blocks() == 0);
}

static void test_chain_first_slice() {
    BlockPool pool(/*block_size=*/16, /*max_free_blocks=*/8);
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

    // Now consume the same 24 bytes from the source; block 0 returns to the pool
    // but block 1 stays live because the slice still references it.
    chain.consume_front(24);
    CHECK(chain.size() == 24);
    CHECK(pool.live_blocks() == 3);
    CHECK(pool.free_blocks() == 0);

    // Dropping the slice releases block 0 (its only remaining ref).
    slice = BlockChain{};
    CHECK(pool.live_blocks() == 2);
    CHECK(pool.free_blocks() == 1);

    // first() clamps to size().
    BlockChain all = chain.first(1000);
    CHECK(all.size() == 24);
}

int main() {
    test_pool_acquire_release();
    test_pool_recycles_same_storage();
    test_blockref_shared_ownership();
    test_free_list_cap();
    test_live_cap_backpressure();
    test_chain_append_and_linearize();
    test_chain_consume_front();
    test_chain_first_slice();

    if (g_failures == 0) {
        std::printf("buffer_smoke: OK\n");
        return 0;
    }
    std::printf("buffer_smoke: %d check(s) failed\n", g_failures);
    return 1;
}
