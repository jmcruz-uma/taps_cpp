// The message memory hook (MessageMemoryConfig), through the public API only:
// every allocation of received message data comes from the application's
// std::pmr resource and returns to it; a received Message stays valid after its
// Connection (or UDP Listener) is gone; the default resource.

#include "taps/taps_api.h"
#include "taps/message_framer.h"

#include <asio.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <vector>

using namespace taps;

static int g_failures = 0;
#define CHECK(cond, name)                                                       \
    do {                                                                       \
        if (cond) { std::printf("PASS  %s\n", name); }                         \
        else { std::printf("FAIL  %s  (%s:%d)\n", name, __FILE__, __LINE__); ++g_failures; } \
    } while (0)

static void fail_on_exception(std::exception_ptr e) {
    if (!e) return;
    try { std::rethrow_exception(e); }
    catch (const std::exception& x) { std::printf("FAIL  coroutine threw: %s\n", x.what()); }
    ++g_failures;
}

// Forwards to new/delete and counts calls and outstanding allocations.
struct CountingResource final : std::pmr::memory_resource {
    std::size_t allocations = 0, deallocations = 0, largest = 0;
    std::size_t outstanding() const { return allocations - deallocations; }
    void* do_allocate(std::size_t n, std::size_t a) override {
        ++allocations;
        if (n > largest) largest = n;
        return std::pmr::new_delete_resource()->allocate(n, a);
    }
    void do_deallocate(void* p, std::size_t n, std::size_t a) override {
        ++deallocations;
        std::pmr::new_delete_resource()->deallocate(p, n, a);
    }
    bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override { return this == &o; }
};

static std::uint8_t pattern(std::size_t k) { return static_cast<std::uint8_t>((k * 7u + 3u) & 0xffu); }

static TransportProperties tcp_props() {
    TransportProperties p;
    p.set(PropertyKey::RELIABILITY, SelectionProperty::REQUIRE);
    return p;
}

static TransportProperties udp_props() {
    TransportProperties p;
    p.set(PropertyKey::RELIABILITY, SelectionProperty::AVOID);
    return p;
}

// A plain asio server: one connection, writes `wire`, closes.
static asio::awaitable<void> raw_server(asio::io_context& ctx, std::uint16_t port, std::vector<std::uint8_t> wire) {
    asio::ip::tcp::acceptor acc(ctx, {asio::ip::make_address("127.0.0.1"), port});
    auto sock = co_await acc.async_accept(asio::use_awaitable);
    co_await asio::async_write(sock, asio::buffer(wire), asio::use_awaitable);
    sock.shutdown(asio::ip::tcp::socket::shutdown_send);
    std::array<char, 16> sink;
    co_await sock.async_read_some(asio::buffer(sink), asio::as_tuple(asio::use_awaitable));
}

// Framed records larger than a block: as_bytes() needs a contiguous buffer. All of
// it — blocks, block lists, that buffer — comes from the application's resource,
// and all of it is returned once the Messages and the Connection are gone.
static void test_all_message_memory_from_resource() {
    constexpr std::uint16_t port = 19940;
    constexpr std::size_t kRecord = 100000;           // spans two or three 64 KiB blocks
    std::vector<std::uint8_t> wire = {0, 0x01, 0x86, 0xa0};   // 100000, big-endian
    for (std::size_t k = 0; k < kRecord; ++k) wire.push_back(pattern(k));
    CountingResource res;
    bool finished = false, exact = false;
    std::size_t outstanding_while_held = 0;
    {
        asio::io_context ctx;
        asio::co_spawn(ctx, raw_server(ctx, port, wire), fail_on_exception);
        asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
            asio::steady_timer t(ctx, std::chrono::milliseconds(100));
            co_await t.async_wait(asio::use_awaitable);
            MessageMemoryConfig memory;
            memory.resource = &res;
            TransportServices ts(ctx, memory);
            auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port}, tcp_props());
            auto cr = co_await pc.initiate();
            if (!cr) co_return;
            auto conn = std::move(*cr);
            conn->set_framer(std::make_unique<LengthPrefixedFramer>());
            auto rr = co_await conn->receive();
            if (rr) {
                const auto bytes = rr->as_bytes();
                exact = bytes.size() == kRecord;
                for (std::size_t k = 0; exact && k < kRecord; ++k)
                    exact = std::to_integer<std::uint8_t>(bytes[k]) == pattern(k);
                outstanding_while_held = res.outstanding();
            }
            co_await conn->close();
            finished = true;
        }, fail_on_exception);
        ctx.run();
    }
    CHECK(finished && exact, "memory: a multi-block record arrives byte-exact through as_bytes()");
    CHECK(outstanding_while_held > 0 && res.largest >= kRecord,
          "memory: the blocks and the contiguous as_bytes() buffer come from the application's resource");
    CHECK(res.allocations > 0 && res.outstanding() == 0,
          "memory: everything taken from the resource is returned");
}

// A received Message stays valid after its Connection is destroyed.
static void test_message_outlives_tcp_connection() {
    constexpr std::uint16_t port = 19941;
    std::vector<std::uint8_t> wire(3000);
    for (std::size_t k = 0; k < wire.size(); ++k) wire[k] = pattern(k);
    std::optional<Message> kept;
    bool finished = false;
    asio::io_context ctx;
    asio::co_spawn(ctx, raw_server(ctx, port, wire), fail_on_exception);
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        asio::steady_timer t(ctx, std::chrono::milliseconds(100));
        co_await t.async_wait(asio::use_awaitable);
        TransportServices ts(ctx);
        auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port}, tcp_props());
        auto cr = co_await pc.initiate();
        if (!cr) co_return;
        (*cr)->set_framer(std::make_unique<PassthroughFramer>(/*gather=*/false));
        auto rr = co_await (*cr)->receive();
        if (rr) kept = std::move(*rr);
        co_await (*cr)->close();
        cr->reset();                       // the Connection is gone
        finished = true;
    }, fail_on_exception);
    ctx.run();
    bool exact = finished && kept && kept->size() == wire.size();
    std::size_t k = 0;
    if (exact)
        for (const auto seg : kept->blocks())
            for (const auto b : seg)
                exact = exact && std::to_integer<std::uint8_t>(b) == wire[k++];
    kept.reset();
    CHECK(exact && k == wire.size(), "lifetime: a received Message stays valid after its TCP Connection is destroyed");
}

// The same for a datagram kept after its UDP Connection and Listener are gone.
static void test_message_outlives_udp_listener() {
    constexpr std::uint16_t port = 19942;
    std::optional<Message> kept;
    bool finished = false;
    asio::io_context ctx;
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
        if (!lr) co_return;
        auto listener = std::move(*lr);
        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        const std::uint8_t d[3] = {7, 8, 9};
        co_await peer.async_send_to(asio::buffer(d), {asio::ip::make_address("127.0.0.1"), port},
                                    asio::use_awaitable);
        auto ar = co_await listener->accept();
        if (!ar) co_return;
        auto rr = co_await (*ar)->receive();
        if (rr) kept = std::move(*rr);
        co_await (*ar)->close();
        ar->reset();
        listener.reset();                  // Connection and Listener are gone
        asio::steady_timer t(ctx, std::chrono::milliseconds(50));
        co_await t.async_wait(asio::use_awaitable);
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(5));
    const auto b = kept ? kept->as_bytes() : std::span<const std::byte>{};
    const bool exact = finished && b.size() == 3 && b[0] == std::byte{7} && b[2] == std::byte{9};
    kept.reset();
    CHECK(exact, "lifetime: a received datagram stays valid after its UDP Connection and Listener are destroyed");
}

static void test_default_resource() {
    const auto options = message_pool_options();
    CHECK(default_message_resource() != nullptr && default_message_resource() == default_message_resource(),
          "default: one process-wide resource");
    CHECK(options.largest_required_pool_block == 64 * 1024 && options.max_blocks_per_chunk == 16,
          "default: pool options for 64 KiB blocks in chunks of 16");
}

int main() {
    test_all_message_memory_from_resource();
    test_message_outlives_tcp_connection();
    test_message_outlives_udp_listener();
    test_default_resource();
    if (g_failures == 0) {
        std::printf("message_memory_test: all checks passed\n");
        return 0;
    }
    std::printf("message_memory_test: %d check(s) failed\n", g_failures);
    return 1;
}
