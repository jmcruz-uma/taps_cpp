// Demonstrates BlockPool::allocate_contiguous(): the hook that lets a
// workload-aware or embedded application redirect Message::ensure_gathered()'s
// final contiguous-buffer allocation (used when a chain spans more than one
// block and the application asks for it as_bytes()) away from the default
// plain `new[]`, to e.g. a static arena.
//
// This closes a gap the existing per-block hook (HeapBlockPool::warm_up(), see
// buffer_smoke.cpp::test_warm_up()) does not cover: warm_up() only pre-mints the
// fixed-size DataBlocks acquire() hands out. It says nothing about the separate,
// variable-sized allocation ensure_gathered() makes to assemble a multi-block
// chain into one contiguous view. Before this hook existed, that allocation was
// unconditional and unreachable from outside the library -- exactly the kind of
// uncontrolled heap use an embedded target cannot accept, regardless of whether
// the per-block side was pooled or not.
//
// Deliberately NOT part of the transport-performance-lab benchmark harness: this
// is a capability demonstration, not a measured comparison arm. The benchmarked
// TAPS client uses the plain default (no custom BlockPool), the same as every
// other implementation in that comparison uses its own idiomatic default -- this
// test exists to show the hook is real and works, not to change any reported
// number.

#include "taps/taps_api.h"

#include "buffer/block.h"
#include "buffer/block_chain.h"
#include "buffer/block_pool.h"
#include "buffer/heap_block_pool.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

using namespace taps;

static int g_failures = 0;

#define CHECK(cond)                                                             \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond);       \
            ++g_failures;                                                      \
        }                                                                     \
    } while (0)

// The simplest possible custom BlockPool strategy: acquire() mints a fresh
// DataBlock directly (no free list -- that reuse story is HeapBlockPool's, and
// is already covered elsewhere), and allocate_contiguous() is redirected to a
// fixed-size arena supplied at construction instead of the default new[]. This
// is intentionally minimal -- a real embedded strategy would size the arena for
// its known workload and likely pool blocks too -- but it is a genuinely
// independent BlockPool implementation, not a wrapper delegating to
// HeapBlockPool (which is `final` and cannot be subclassed for exactly this
// kind of partial override).
class ArenaGatherPool : public BlockPool {
public:
    ArenaGatherPool(std::size_t block_size, std::size_t arena_size)
        : block_size_(block_size),
          arena_(std::make_unique_for_overwrite<std::byte[]>(arena_size)),
          arena_size_(arena_size) {}

    BlockRef acquire() override {
        DataBlock* blk = new DataBlock(this, block_size_);
        ++live_;
        return BlockRef(blk, 0, 0);
    }
    std::size_t block_size() const noexcept override { return block_size_; }
    bool        at_capacity() const noexcept override { return false; }
    std::size_t free_blocks() const noexcept override { return 0; }
    std::size_t live_blocks() const noexcept override { return live_; }

    std::shared_ptr<std::byte[]> allocate_contiguous(std::size_t n) const override {
        ++gather_calls;
        last_gather_n = n;
        CHECK(n <= arena_size_);   // the test sizes its arena to fit; a real
                                   // strategy would need its own overflow policy
        // Hand back a view of OUR arena via a non-owning shared_ptr (no-op
        // deleter) -- proves the buffer really came from here, not from a fresh
        // heap allocation, without taking ownership away from this pool.
        return std::shared_ptr<std::byte[]>(arena_.get(), [](std::byte*) {});
    }

    mutable int         gather_calls  = 0;
    mutable std::size_t last_gather_n = 0;

    // Test-only accessor: lets the test confirm a gathered Message's bytes
    // physically live inside this pool's own arena, not some unrelated
    // allocation the hook silently failed to redirect.
    const std::byte* arena_ptr_for_test() const noexcept { return arena_.get(); }

private:
    void recycle(DataBlock* blk) noexcept override {
        --live_;
        delete blk;   // no free list in this minimal strategy
    }

    std::size_t                  block_size_;
    std::unique_ptr<std::byte[]> arena_;
    std::size_t                  arena_size_;
    std::size_t                  live_ = 0;
};

// Builds a chain holding a copy of `s`, split into `block`-sized links, drawn
// from `pool`. Mirrors message_test.cpp's helper of the same shape.
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

static bool bytes_equal(std::span<const std::byte> b, const std::string& s) {
    return b.size() == s.size() && std::memcmp(b.data(), s.data(), s.size()) == 0;
}

// The headline case: gathering a multi-block chain uses the pool's hook, not a
// fresh heap allocation -- and the resulting bytes genuinely live inside the
// pool's own arena.
static void test_multiblock_gather_uses_pool_arena() {
    const std::string s = "the quick brown fox jumps over the lazy dog, exactly.";
    ArenaGatherPool pool(/*block_size=*/8, /*arena_size=*/s.size());
    auto chain = make_chain(pool, s, 8);
    CHECK(chain->block_count() > 1);   // must actually exercise the gather path
    CHECK(pool.gather_calls == 0);     // building the chain must not gather anything

    Message m(chain);
    const auto bytes = m.as_bytes();
    CHECK(bytes_equal(bytes, s));

    CHECK(pool.gather_calls == 1);
    CHECK(pool.last_gather_n == s.size());

    // The strongest check: the returned bytes must physically lie within the
    // pool's own arena, not in some unrelated heap allocation the hook was
    // bypassed for.
    const auto* arena_begin = pool.arena_ptr_for_test();
    const auto* arena_end   = arena_begin + s.size();
    CHECK(bytes.data() >= reinterpret_cast<const std::byte*>(arena_begin));
    CHECK(bytes.data() + bytes.size() <= reinterpret_cast<const std::byte*>(arena_end));

    // as_bytes() caches: a second call must not gather again.
    (void)m.as_bytes();
    CHECK(pool.gather_calls == 1);
}

// A single-block chain must keep taking the zero-copy view path (already tested
// against HeapBlockPool in message_test.cpp) -- confirmed here specifically
// against a pool whose allocate_contiguous() we can observe, so "the hook is
// never called when it isn't needed" is a checked property, not an assumption.
static void test_single_block_never_calls_hook() {
    const std::string s = "fits in one block";
    ArenaGatherPool pool(/*block_size=*/64, /*arena_size=*/64);
    auto chain = make_chain(pool, s, 64);
    CHECK(chain->block_count() == 1);

    Message m(chain);
    CHECK(bytes_equal(m.as_bytes(), s));
    CHECK(pool.gather_calls == 0);
    CHECK(m.as_bytes().data() == chain->begin()->bytes().data());   // view in place
}

// The default strategy (no override) must behave exactly as before this hook
// existed -- a plain heap allocation -- so nothing about the default path
// regresses for a caller that never installs a custom BlockPool.
static void test_default_pool_still_gathers_correctly() {
    const std::string s = "default HeapBlockPool path, unchanged by the new hook";
    HeapBlockPool pool(/*block_size=*/12);
    auto chain = make_chain(pool, s, 12);
    CHECK(chain->block_count() > 1);

    Message m(chain);
    CHECK(bytes_equal(m.as_bytes(), s));
}

int main() {
    test_multiblock_gather_uses_pool_arena();
    test_single_block_never_calls_hook();
    test_default_pool_still_gathers_correctly();

    if (g_failures == 0) {
        std::printf("gather_allocator_hook_test: OK\n");
        return 0;
    }
    std::printf("gather_allocator_hook_test: %d check(s) failed\n", g_failures);
    return 1;
}
