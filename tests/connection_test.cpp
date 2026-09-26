// End-to-end tests of plain TCP and UDP connections over the taps_cpp public API on
// real loopback sockets: delivery and end of stream with and without a framer,
// records around block boundaries, a stream ending inside a record, whole-transfer
// delivery, echoing received (chain-backed) Messages, receive-pool exhaustion as seen
// by receive(), a pending receive() interrupted by abort(), and UDP datagram echo.

#include "taps/taps_api.h"
#include "taps/message_framer.h"

#include "buffer/heap_block_pool.h"

#include <asio.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <vector>

using namespace taps;

static int g_failures = 0;
#define CHECK(cond, name)                                                       \
    do {                                                                       \
        if (cond) { std::printf("PASS  %s\n", name); }                         \
        else { std::printf("FAIL  %s  (%s:%d)\n", name, __FILE__, __LINE__); ++g_failures; } \
    } while (0)

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

// Deterministic content: byte k of payload i.
static std::uint8_t pattern(std::size_t i, std::size_t k) {
    return static_cast<std::uint8_t>((i * 131u + k * 7u) & 0xffu);
}

static std::vector<std::uint8_t> payload(std::size_t i, std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t k = 0; k < n; ++k)
        v[k] = pattern(i, k);
    return v;
}

static bool equals(std::span<const std::byte> got, const std::vector<std::uint8_t>& want) {
    if (got.size() != want.size())
        return false;
    for (std::size_t k = 0; k < want.size(); ++k)
        if (std::to_integer<std::uint8_t>(got[k]) != want[k])
            return false;
    return true;
}

// The Message's bytes gathered from its segments (checks blocks() independently of
// as_bytes()).
static std::vector<std::byte> from_blocks(const Message& m) {
    std::vector<std::byte> out;
    for (const auto seg : m.blocks())
        out.insert(out.end(), seg.begin(), seg.end());
    return out;
}

static asio::awaitable<std::unique_ptr<Listener>> listen_tcp(TransportServices& ts, std::uint16_t port) {
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props());
    if (!lr) {
        std::printf("FAIL  listen on %u: %s\n", port, lr.error().message().c_str());
        ++g_failures;
        co_return nullptr;
    }
    co_return std::move(*lr);
}

static asio::awaitable<std::unique_ptr<Connection>> connect_tcp(TransportServices& ts, std::uint16_t port) {
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port}, tcp_props());
    auto cr = co_await pc.initiate();
    if (!cr) {
        std::printf("FAIL  initiate to %u: %s\n", port, cr.error().message().c_str());
        ++g_failures;
        co_return nullptr;
    }
    co_return std::move(*cr);
}

// Runs a server and a client coroutine on a fresh io_context; the client starts after
// a short delay so the server is listening, and stops the context when done.
template <typename Server, typename Client>
static void scenario(Server server, Client client) {
    asio::io_context ctx;
    asio::co_spawn(ctx, server(ctx), asio::detached);
    asio::co_spawn(ctx, [&ctx, client]() -> asio::awaitable<void> {
        asio::steady_timer t(ctx, std::chrono::milliseconds(100));
        co_await t.async_wait(asio::use_awaitable);
        co_await client(ctx);
        ctx.stop();
    }, asio::detached);
    ctx.run();
}

// A server that accepts one connection, sends `data` as one Message and closes.
static auto send_once_server(std::uint16_t port, std::vector<std::uint8_t> data) {
    return [port, data = std::move(data)](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto l = co_await listen_tcp(ts, port);
        if (!l) co_return;
        auto ar = co_await l->accept();
        if (!ar) { ++g_failures; co_return; }
        auto conn = std::move(*ar);
        co_await conn->send(make_message_view(std::span<const std::uint8_t>(data)));
        co_await conn->close();
    };
}

// ---------------------------------------------------------------------------
// No framer: the stream arrives as partial Messages, then one empty final Message.
// ---------------------------------------------------------------------------
static void test_unframed_stream() {
    constexpr std::uint16_t port = 19980;
    const auto data = payload(1, 1u << 20);
    scenario(send_once_server(port, data), [&data](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        std::vector<std::byte> got;
        bool partial_flags_ok = true, ended = false;
        for (;;) {
            auto rr = co_await conn->receive();
            if (!rr) break;
            auto m = std::move(*rr);
            if (m.size() == 0) { ended = m.is_end_of_message(); break; }
            partial_flags_ok = partial_flags_ok && !m.is_end_of_message();
            const auto b = m.as_bytes();
            got.insert(got.end(), b.begin(), b.end());
        }
        CHECK(equals(got, data), "unframed: whole stream arrives byte-exact");
        CHECK(partial_flags_ok, "unframed: data Messages are partial (end_of_message == false)");
        CHECK(ended, "unframed: end of stream is an empty Message with end_of_message == true");
        CHECK(conn->state() == ConnectionState::CLOSED, "unframed: connection is CLOSED after end of stream");
        auto again = co_await conn->receive();
        CHECK(!again, "unframed: receive() after end of stream fails");
    });
}

// ---------------------------------------------------------------------------
// LengthPrefixedFramer: one Message per record, including records around the 64 KiB
// block size, then an empty final Message.
// ---------------------------------------------------------------------------
static const std::vector<std::size_t> kRecordSizes = {
    1, 100, 65531, 65532, 65535, 65536, 65537, 131072, 200000, 3};

static void test_framed_records() {
    constexpr std::uint16_t port = 19981;
    scenario(
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto l = co_await listen_tcp(ts, port);
            if (!l) co_return;
            auto ar = co_await l->accept();
            if (!ar) { ++g_failures; co_return; }
            auto conn = std::move(*ar);
            conn->set_framer(std::make_unique<LengthPrefixedFramer>());
            for (std::size_t i = 0; i < kRecordSizes.size(); ++i) {
                const auto rec = payload(i, kRecordSizes[i]);
                co_await conn->send(make_message_view(std::span<const std::uint8_t>(rec)));
            }
            co_await conn->close();
        },
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto conn = co_await connect_tcp(ts, port);
            if (!conn) co_return;
            conn->set_framer(std::make_unique<LengthPrefixedFramer>());
            std::size_t exact = 0, exact_blocks = 0, eom = 0;
            for (std::size_t i = 0; i < kRecordSizes.size(); ++i) {
                auto rr = co_await conn->receive();
                if (!rr) break;
                auto m = std::move(*rr);
                const auto want = payload(i, kRecordSizes[i]);
                if (equals(m.as_bytes(), want)) ++exact;
                if (equals(from_blocks(m), want)) ++exact_blocks;
                if (m.is_end_of_message()) ++eom;
            }
            CHECK(exact == kRecordSizes.size(), "framed: every record arrives byte-exact via as_bytes()");
            CHECK(exact_blocks == kRecordSizes.size(), "framed: every record arrives byte-exact via blocks()");
            CHECK(eom == kRecordSizes.size(), "framed: every record is a complete Message");
            auto last = co_await conn->receive();
            CHECK(last && last->size() == 0 && last->is_end_of_message(),
                  "framed: end of stream is an empty Message with end_of_message == true");
            CHECK(conn->state() == ConnectionState::CLOSED, "framed: connection is CLOSED after end of stream");
        });
}

// ---------------------------------------------------------------------------
// The peer closes in the middle of a record (raw socket server: header announces
// 1000 bytes, only 500 follow).
// ---------------------------------------------------------------------------
static void test_framed_eof_inside_record() {
    constexpr std::uint16_t port = 19982;
    scenario(
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            asio::ip::tcp::acceptor acc(ctx, {asio::ip::make_address("127.0.0.1"), port});
            auto sock = co_await acc.async_accept(asio::use_awaitable);
            const std::uint8_t header[4] = {0, 0, 0x03, 0xe8};   // 1000, big-endian
            const auto half = payload(0, 500);
            co_await asio::async_write(sock, asio::buffer(header), asio::use_awaitable);
            co_await asio::async_write(sock, asio::buffer(half), asio::use_awaitable);
            sock.shutdown(asio::ip::tcp::socket::shutdown_both);
            sock.close();
        },
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto conn = co_await connect_tcp(ts, port);
            if (!conn) co_return;
            conn->set_framer(std::make_unique<LengthPrefixedFramer>());
            auto rr = co_await conn->receive();
            CHECK(rr && rr->size() == 0 && rr->is_end_of_message(),
                  "framed: end of stream inside a record yields an empty final Message");
            CHECK(conn->state() == ConnectionState::CLOSED,
                  "framed: connection is CLOSED after end of stream inside a record");
        });
}

// ---------------------------------------------------------------------------
// PassthroughFramer: the whole transfer as one Message, gathered or as a chain.
// ---------------------------------------------------------------------------
static void test_whole_transfer(bool gather, std::uint16_t port) {
    const auto data = payload(2, 1u << 20);
    scenario(send_once_server(port, data), [&data, gather, port](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        conn->set_framer(std::make_unique<PassthroughFramer>(gather));
        auto rr = co_await conn->receive();
        if (!rr) { CHECK(false, "whole transfer: receive() succeeds"); co_return; }
        auto m = std::move(*rr);
        if (gather) {
            CHECK(equals(m.as_bytes(), data), "whole transfer (gather): one Message, byte-exact");
            CHECK(equals(from_blocks(m), data) && m.blocks().size() > 1,
                  "whole transfer (gather): blocks() still exposes the underlying segments, byte-exact");
        } else {
            CHECK(equals(from_blocks(m), data), "whole transfer (chain): one Message, byte-exact via blocks()");
            CHECK(m.blocks().size() > 1, "whole transfer (chain): delivered as several segments");
            CHECK(equals(m.as_bytes(), data), "whole transfer (chain): as_bytes() gathers byte-exact");
        }
        CHECK(m.is_end_of_message(), "whole transfer: the Message is complete");
    });
}

// ---------------------------------------------------------------------------
// Echo: the server sends back the Messages it received (chain-backed Messages on the
// send path), with and without a framer.
// ---------------------------------------------------------------------------
static void test_echo(bool framed, std::uint16_t port, const char* name) {
    const std::vector<std::size_t> sizes = framed ? std::vector<std::size_t>{5, 8192, 200000, 1}
                                                  : std::vector<std::size_t>{4096};
    scenario(
        [framed, port](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto l = co_await listen_tcp(ts, port);
            if (!l) co_return;
            auto ar = co_await l->accept();
            if (!ar) { ++g_failures; co_return; }
            auto conn = std::move(*ar);
            if (framed) conn->set_framer(std::make_unique<LengthPrefixedFramer>());
            for (;;) {
                auto rr = co_await conn->receive();
                if (!rr) break;
                auto m = std::move(*rr);
                if (m.size() == 0) break;
                if (!(co_await conn->send(m))) break;
                if (!framed) break;
            }
            co_await conn->close();
        },
        [framed, sizes, name, port](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto conn = co_await connect_tcp(ts, port);
            if (!conn) co_return;
            if (framed) conn->set_framer(std::make_unique<LengthPrefixedFramer>());
            std::size_t exact = 0;
            for (std::size_t i = 0; i < sizes.size(); ++i) {
                const auto out = payload(i, sizes[i]);
                if (!(co_await conn->send(make_message_view(std::span<const std::uint8_t>(out))))) break;
                std::vector<std::byte> back;
                while (back.size() < out.size()) {   // unframed echoes may come in pieces
                    auto rr = co_await conn->receive();
                    if (!rr || rr->size() == 0) break;
                    const auto b = rr->as_bytes();
                    back.insert(back.end(), b.begin(), b.end());
                }
                if (equals(back, out)) ++exact;
            }
            CHECK(exact == sizes.size(), name);
            co_await conn->close();
        });
}

// ---------------------------------------------------------------------------
// Receive-pool exhaustion: with a live-block cap, a client that keeps every delivered
// Message alive eventually gets an error from receive() instead of more data.
// ---------------------------------------------------------------------------
struct CappedPoolFactory final : BlockPoolFactory {
    std::unique_ptr<BlockPool> make() const override {
        return std::make_unique<HeapBlockPool>(/*block_size=*/1024, /*max_free_blocks=*/4,
                                               /*max_live_blocks=*/4);
    }
};

static void test_pool_exhaustion() {
    constexpr std::uint16_t port = 19986;
    const auto data = payload(3, 64u * 1024);
    scenario(send_once_server(port, data), [](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx, std::make_shared<CappedPoolFactory>());
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        std::vector<Message> kept;
        bool failed = false;
        for (int i = 0; i < 1000; ++i) {
            auto rr = co_await conn->receive();
            if (!rr) { failed = true; break; }
            if (rr->size() == 0) break;
            kept.push_back(std::move(*rr));
        }
        CHECK(failed, "pool cap: receive() fails once every block is held by the application");
        CHECK(conn->state() == ConnectionState::ERROR, "pool cap: connection is in ERROR after the failure");
    });
}

// ---------------------------------------------------------------------------
// A pending receive() completes with an error when the connection is aborted.
// ---------------------------------------------------------------------------
static void test_receive_interrupted_by_abort() {
    constexpr std::uint16_t port = 19987;
    asio::io_context ctx;
    std::unique_ptr<Listener> listener;
    std::unique_ptr<Connection> server_conn;
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        listener = co_await listen_tcp(ts, port);
        if (!listener) co_return;
        auto ar = co_await listener->accept();
        if (ar) server_conn = std::move(*ar);   // kept open, never sends
    }, asio::detached);
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        asio::steady_timer t(ctx, std::chrono::milliseconds(100));
        co_await t.async_wait(asio::use_awaitable);
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) { ctx.stop(); co_return; }
        Connection* raw = conn.get();
        asio::co_spawn(ctx, [&ctx, raw]() -> asio::awaitable<void> {
            asio::steady_timer t2(ctx, std::chrono::milliseconds(100));
            co_await t2.async_wait(asio::use_awaitable);
            co_await raw->abort();
        }, asio::detached);
        auto rr = co_await conn->receive();
        CHECK(!rr, "abort: a pending receive() completes with an error");
        CHECK(conn->state() != ConnectionState::ESTABLISHED, "abort: connection is no longer ESTABLISHED");
        ctx.stop();
    }, asio::detached);
    ctx.run();
}

// ---------------------------------------------------------------------------
// UDP: datagrams echoed through a listener, one Message per datagram.
// ---------------------------------------------------------------------------
static void test_udp_echo() {
    constexpr std::uint16_t port = 19988;
    const std::vector<std::size_t> sizes = {1, 1400, 65507};
    scenario(
        [sizes](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
            if (!lr) { std::printf("FAIL  udp listen: %s\n", lr.error().message().c_str()); ++g_failures; co_return; }
            auto l = std::move(*lr);
            auto ar = co_await l->accept();
            if (!ar) { ++g_failures; co_return; }
            auto conn = std::move(*ar);
            for (std::size_t i = 0; i < sizes.size(); ++i) {
                auto rr = co_await conn->receive();
                if (!rr) break;
                if (!(co_await conn->send(*rr))) break;
            }
            asio::steady_timer t(ctx, std::chrono::milliseconds(200));   // let the last reply leave
            co_await t.async_wait(asio::use_awaitable);
        },
        [sizes](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port}, udp_props());
            auto cr = co_await pc.initiate();
            if (!cr) { std::printf("FAIL  udp initiate: %s\n", cr.error().message().c_str()); ++g_failures; co_return; }
            auto conn = std::move(*cr);
            std::size_t exact = 0;
            for (std::size_t i = 0; i < sizes.size(); ++i) {
                const auto out = payload(i, sizes[i]);
                if (!(co_await conn->send(make_message_view(std::span<const std::uint8_t>(out))))) break;
                auto rr = co_await conn->receive();
                if (!rr) break;
                if (equals(rr->as_bytes(), out) && rr->is_end_of_message()) ++exact;
            }
            CHECK(exact == sizes.size(), "udp: each datagram is echoed as one complete Message, byte-exact");
        });
}

int main() {
    test_unframed_stream();
    test_framed_records();
    test_framed_eof_inside_record();
    test_whole_transfer(/*gather=*/true, 19983);
    test_whole_transfer(/*gather=*/false, 19984);
    test_echo(/*framed=*/false, 19985, "echo: an unframed received Message is sent back byte-exact");
    test_echo(/*framed=*/true, 19989, "echo: framed received Messages (up to 200000 bytes) are sent back byte-exact");
    test_pool_exhaustion();
    test_receive_interrupted_by_abort();
    test_udp_echo();

    if (g_failures == 0) {
        std::printf("connection_test: all checks passed\n");
        return 0;
    }
    std::printf("connection_test: %d check(s) failed\n", g_failures);
    return 1;
}
