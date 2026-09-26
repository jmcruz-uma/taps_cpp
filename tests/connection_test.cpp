// End-to-end tests of plain TCP and UDP connections over the taps_cpp public API on
// real loopback sockets: delivery and end of stream with and without a framer,
// records around block boundaries, a stream ending inside a record or a header,
// a framer that makes no progress, whole-transfer delivery, echoing received
// (chain-backed) Messages, receive-pool exhaustion, a pending receive() interrupted
// by abort(), replying after the peer's end of stream, close() with unread data or
// a pending receive(), abort() as a reset, establishment and listen errors, UDP
// datagram echo, UDP idle eviction, and the UDP Listener's lifetime (passive
// Connections outlive it; stop() only stops accepting new sources). Errors are checked as RFC 9622 event + RFC 9623 Appendix B reason.

#include "taps/taps_api.h"
#include "taps/message_framer.h"

#include <asio.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <utility>
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

// Completion handler for spawned coroutines: an escaping exception is a failure.
static void fail_on_exception(std::exception_ptr e) {
    if (!e) return;
    try { std::rethrow_exception(e); }
    catch (const std::exception& x) { std::printf("FAIL  coroutine threw: %s\n", x.what()); }
    ++g_failures;
}

// A test body that never reached its end is a failure.
static void check_finished(bool finished, const char* test) {
    if (!finished) {
        std::printf("FAIL  %s: did not finish\n", test);
        ++g_failures;
    }
}

template <typename T>
static bool is_error(const Result<T>& r, ErrorEvent event, ErrorReason reason) {
    return !r && r.error().event() == event && r.error().reason() == reason;
}

// A plain asio server that writes `bytes` to the first connection and closes it.
static auto raw_server(std::uint16_t port, std::vector<std::uint8_t> bytes) {
    return [port, bytes = std::move(bytes)](asio::io_context& ctx) -> asio::awaitable<void> {
        asio::ip::tcp::acceptor acc(ctx, {asio::ip::make_address("127.0.0.1"), port});
        auto sock = co_await acc.async_accept(asio::use_awaitable);
        co_await asio::async_write(sock, asio::buffer(bytes), asio::use_awaitable);
        sock.shutdown(asio::ip::tcp::socket::shutdown_both);
        sock.close();
    };
}

// Runs a server and a client coroutine on a fresh io_context; the client starts after
// a short delay so the server is listening, and stops the context when done.
// An exception escaping either side, or a client that never finishes, is a failure.
template <typename Server, typename Client>
static void scenario(Server server, Client client) {
    asio::io_context ctx;
    bool client_finished = false;
    asio::co_spawn(ctx, server(ctx), fail_on_exception);
    asio::co_spawn(ctx, [&ctx, client, &client_finished]() -> asio::awaitable<void> {
        asio::steady_timer t(ctx, std::chrono::milliseconds(100));
        co_await t.async_wait(asio::use_awaitable);
        co_await client(ctx);
        client_finished = true;
        ctx.stop();
    }, fail_on_exception);
    ctx.run();
    check_finished(client_finished, "scenario client");
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
        CHECK(conn->state() == ConnectionState::ESTABLISHED && conn->can_send() && !conn->can_receive(),
              "unframed: after the end of stream the connection can still send, not receive");
        auto again = co_await conn->receive();
        CHECK(is_error(again, ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE),
              "unframed: receive() after end of stream is RECEIVE_ERROR / INVALID_STATE");
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
            CHECK(conn->state() == ConnectionState::ESTABLISHED && conn->can_send() && !conn->can_receive(),
                  "framed: after the end of stream the connection can still send, not receive");
        });
}

// ---------------------------------------------------------------------------
// The peer closes in the middle of a record body (header announces 1000 bytes, only
// 500 follow): the 500 bytes arrive as a partial Message, then a ReceiveError
// (RFC 9623 Section 5.2; RFC 9622 Sections 9.3.2.2 and 9.3.2.3).
// ---------------------------------------------------------------------------
static void test_framed_eof_inside_record() {
    constexpr std::uint16_t port = 19982;
    std::vector<std::uint8_t> wire = {0, 0, 0x03, 0xe8};   // 1000, big-endian
    const auto half = payload(0, 500);
    wire.insert(wire.end(), half.begin(), half.end());
    scenario(raw_server(port, wire), [&half](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        conn->set_framer(std::make_unique<LengthPrefixedFramer>());
        auto partial = co_await conn->receive();
        CHECK(partial && equals(partial->as_bytes(), half) && !partial->is_end_of_message(),
              "framed, EOF in body: the bytes that arrived are a partial Message (end_of_message false)");
        auto err = co_await conn->receive();
        CHECK(is_error(err, ErrorEvent::RECEIVE_ERROR, ErrorReason::DEFRAMING_FAILED),
              "framed, EOF in body: then RECEIVE_ERROR / DEFRAMING_FAILED");
        CHECK(conn->state() == ConnectionState::ESTABLISHED && conn->can_send() && !conn->can_receive(),
              "framed, EOF in body: the connection can still send, not receive");
        auto again = co_await conn->receive();
        CHECK(is_error(again, ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE),
              "framed, EOF in body: a further receive() is RECEIVE_ERROR / INVALID_STATE");
    });
}

// The peer closes inside a record header, after one complete record: the record is
// delivered, then a ReceiveError; the header bytes are not Message content.
static void test_framed_eof_inside_header() {
    constexpr std::uint16_t port = 19990;
    std::vector<std::uint8_t> wire = {0, 0, 0, 10};
    const auto body = payload(0, 10);
    wire.insert(wire.end(), body.begin(), body.end());
    wire.insert(wire.end(), {0, 0});                       // half a header
    scenario(raw_server(port, wire), [&body](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        conn->set_framer(std::make_unique<LengthPrefixedFramer>());
        auto first = co_await conn->receive();
        CHECK(first && equals(first->as_bytes(), body) && first->is_end_of_message(),
              "framed, EOF in header: the complete record before it is delivered");
        auto err = co_await conn->receive();
        CHECK(is_error(err, ErrorEvent::RECEIVE_ERROR, ErrorReason::DEFRAMING_FAILED),
              "framed, EOF in header: then RECEIVE_ERROR / DEFRAMING_FAILED");
        CHECK(conn->state() == ConnectionState::ESTABLISHED && conn->can_send() && !conn->can_receive(),
              "framed, EOF in header: the connection can still send, not receive");
    });
}

// A framer whose Emit consumes nothing would be asked forever; receive() refuses it.
struct NoProgressFramer final : MessageFramer {
    ParseResult parse(const ReceiveCursor&, bool) override { return ParseResult::emit(0); }
    std::size_t write_header(const Message&, std::span<std::byte>) override { return 0; }
    std::size_t max_header_size() const noexcept override { return 0; }
};

static void test_framer_without_progress() {
    constexpr std::uint16_t port = 19991;
    scenario(send_once_server(port, payload(0, 100)), [](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        conn->set_framer(std::make_unique<NoProgressFramer>());
        auto err = co_await conn->receive();
        CHECK(is_error(err, ErrorEvent::RECEIVE_ERROR, ErrorReason::DEFRAMING_FAILED),
              "framer emitting a record that consumes nothing: RECEIVE_ERROR / DEFRAMING_FAILED");
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
        auto end = co_await conn->receive();
        CHECK(end && end->size() == 0 && end->is_end_of_message(),
              "whole transfer: then the end of stream (empty Message)");
        CHECK(conn->state() == ConnectionState::ESTABLISHED && conn->can_send() && !conn->can_receive(),
              "whole transfer: after the end the connection can still send, not receive");
        auto again = co_await conn->receive();
        CHECK(is_error(again, ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE),
              "whole transfer: a further receive() is RECEIVE_ERROR / INVALID_STATE");
    });
}

// An empty transfer: only the end of stream, then errors.
static void test_whole_transfer_empty() {
    constexpr std::uint16_t port = 19992;
    scenario(send_once_server(port, {}), [](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        conn->set_framer(std::make_unique<PassthroughFramer>());
        auto end = co_await conn->receive();
        CHECK(end && end->size() == 0 && end->is_end_of_message(),
              "whole transfer, empty: the end of stream (empty Message)");
        auto again = co_await conn->receive();
        CHECK(is_error(again, ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE),
              "whole transfer, empty: a further receive() is RECEIVE_ERROR / INVALID_STATE");
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
// Message alive gets RECEIVE_ERROR / RESOURCE_EXHAUSTED. A ReceiveError does not end
// the Connection (RFC 9622 Section 9.3.2.3): once the Messages are released, the
// rest of the stream arrives.
// ---------------------------------------------------------------------------
// 1 KiB blocks, at most 4 live per Connection.
static MessageMemoryConfig capped_memory() {
    MessageMemoryConfig memory;
    memory.block_size = 1024;
    memory.max_live_blocks = 4;
    return memory;
}

static void test_pool_exhaustion() {
    constexpr std::uint16_t port = 19986;
    const auto data = payload(3, 64u * 1024);
    scenario(send_once_server(port, data), [&data](asio::io_context& ctx) -> asio::awaitable<void> {
        TransportServices ts(ctx, capped_memory());
        auto conn = co_await connect_tcp(ts, port);
        if (!conn) co_return;
        std::vector<Message> kept;
        std::vector<std::uint8_t> got;
        bool exhausted = false;
        for (int i = 0; i < 1000; ++i) {
            auto rr = co_await conn->receive();
            if (!rr) {
                exhausted = is_error(rr, ErrorEvent::RECEIVE_ERROR, ErrorReason::RESOURCE_EXHAUSTED);
                break;
            }
            for (const auto b : rr->as_bytes())
                got.push_back(std::to_integer<std::uint8_t>(b));
            kept.push_back(std::move(*rr));
        }
        CHECK(exhausted, "pool cap: receive() fails with RECEIVE_ERROR / RESOURCE_EXHAUSTED");
        CHECK(conn->state() == ConnectionState::ESTABLISHED, "pool cap: the connection stays ESTABLISHED");
        kept.clear();
        bool ended = false;
        for (int i = 0; i < 1000 && !ended; ++i) {
            auto rr = co_await conn->receive();
            if (!rr) break;
            for (const auto b : rr->as_bytes())
                got.push_back(std::to_integer<std::uint8_t>(b));
            ended = rr->size() == 0 && rr->is_end_of_message();
        }
        CHECK(ended && got == data, "pool cap: after releasing Messages the rest of the stream arrives byte-exact");
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
    bool finished = false;
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        listener = co_await listen_tcp(ts, port);
        if (!listener) co_return;
        auto ar = co_await listener->accept();
        if (ar) server_conn = std::move(*ar);   // kept open, never sends
    }, fail_on_exception);
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
        CHECK(is_error(rr, ErrorEvent::CONNECTION_ERROR, ErrorReason::LOCAL_ABORT),
              "abort: a pending receive() completes with CONNECTION_ERROR / LOCAL_ABORT");
        CHECK(conn->state() == ConnectionState::CLOSED, "abort: connection is CLOSED");
        finished = true;
        ctx.stop();
    }, fail_on_exception);
    ctx.run();
    check_finished(finished, "abort test");
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

// ---------------------------------------------------------------------------
// Establishment and listen errors (RFC 9622 Sections 7.1 and 7.2).
// ---------------------------------------------------------------------------
static void test_establishment_errors() {
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", 19993}, tcp_props());
        auto cr = co_await pc.initiate();
        CHECK(is_error(cr, ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::ESTABLISHMENT_FAILED),
              "initiate to a port nobody listens on: ESTABLISHMENT_ERROR / ESTABLISHMENT_FAILED");

        auto first = co_await ts.listen(LocalEndpoint{"127.0.0.1", 19994}, tcp_props());
        auto second = co_await ts.listen(LocalEndpoint{"127.0.0.1", 19994}, tcp_props());
        CHECK(first && is_error(second, ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::LOCAL_ENDPOINT_UNAVAILABLE),
              "listen on a port already in use: ESTABLISHMENT_ERROR / LOCAL_ENDPOINT_UNAVAILABLE");
        finished = true;
    }, fail_on_exception);
    ctx.run();
    check_finished(finished, "establishment test");
}

// ---------------------------------------------------------------------------
// UDP: a passive connection with no traffic is evicted by the listener's idle sweep.
// ---------------------------------------------------------------------------
static void test_udp_idle_eviction() {
    constexpr std::uint16_t port = 19995;
    ::setenv("TAPS_UDP_IDLE_SECS", "1", 1);
    ::setenv("TAPS_UDP_SWEEP_SECS", "1", 1);
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
        if (!lr) { CHECK(false, "udp idle: listen"); co_return; }
        auto listener = std::move(*lr);

        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        const std::uint8_t one = 1;
        co_await peer.async_send_to(asio::buffer(&one, 1),
                                    {asio::ip::make_address("127.0.0.1"), port}, asio::use_awaitable);

        auto ar = co_await listener->accept();
        if (!ar) { CHECK(false, "udp idle: accept"); co_return; }
        auto conn = std::move(*ar);
        auto first = co_await conn->receive();
        auto evicted = co_await conn->receive();   // no more traffic: the sweep evicts it
        CHECK(first && is_error(evicted, ErrorEvent::CONNECTION_ERROR, ErrorReason::IDLE_TIMEOUT),
              "udp idle: an idle passive connection ends with CONNECTION_ERROR / IDLE_TIMEOUT");
        CHECK(conn->state() == ConnectionState::CLOSED, "udp idle: connection is CLOSED");

        // The listener's receive loop must observe stop() before the listener goes away.
        co_await listener->stop();
        asio::steady_timer t(ctx, std::chrono::milliseconds(50));
        co_await t.async_wait(asio::use_awaitable);
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(10));
    check_finished(finished, "udp idle test");
    ::unsetenv("TAPS_UDP_IDLE_SECS");
    ::unsetenv("TAPS_UDP_SWEEP_SECS");
}

// ---------------------------------------------------------------------------
// End of the peer's stream and Close (RFC 9623 Section 10.1, TCP).
// ---------------------------------------------------------------------------

// Waits (up to one second) for the other side of a scenario to set `done`.
static asio::awaitable<bool> wait_for(asio::io_context& ctx, const bool& done) {
    for (int i = 0; i < 100 && !done; ++i) {
        asio::steady_timer t(ctx, std::chrono::milliseconds(10));
        co_await t.async_wait(asio::use_awaitable);
    }
    co_return done;
}

// Reads until the connection ends; returns the bytes and how it ended.
static asio::awaitable<std::pair<std::vector<std::uint8_t>, asio::error_code>>
read_to_end(asio::ip::tcp::socket& sock) {
    std::vector<std::uint8_t> got;
    std::array<std::uint8_t, 65536> buf;
    for (;;) {
        auto [ec, n] = co_await sock.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        got.insert(got.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
        if (ec) co_return std::pair{std::move(got), ec};
    }
}

// The peer sends a request and ends its side; the Connection receives it to the end,
// can still send, answers, and closes. The peer gets the whole answer and a clean end.
static void test_reply_after_peer_end() {
    constexpr std::uint16_t port = 19996;
    const auto request = payload(4, 1000);
    const auto response = payload(5, 1u << 20);
    bool server_done = false;
    scenario(
        [&](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto l = co_await listen_tcp(ts, port);
            if (!l) co_return;
            auto ar = co_await l->accept();
            if (!ar) { ++g_failures; co_return; }
            auto conn = std::move(*ar);
            std::vector<std::uint8_t> got;
            for (;;) {
                auto rr = co_await conn->receive();
                if (!rr) break;
                for (const auto b : rr->as_bytes()) got.push_back(std::to_integer<std::uint8_t>(b));
                if (rr->is_end_of_message()) break;
            }
            CHECK(got == request && conn->state() == ConnectionState::ESTABLISHED &&
                      conn->can_send() && !conn->can_receive(),
                  "half-close: after the peer's end the request is complete and the connection can still send");
            auto sr = co_await conn->send(make_message_view(std::span<const std::uint8_t>(response)));
            CHECK(static_cast<bool>(sr), "half-close: send() after the peer's end succeeds");
            auto cr = co_await conn->close();
            CHECK(cr && conn->state() == ConnectionState::CLOSED, "half-close: close() completes, CLOSED");
            server_done = true;
        },
        [&](asio::io_context& ctx) -> asio::awaitable<void> {
            asio::ip::tcp::socket sock(ctx);
            co_await sock.async_connect({asio::ip::make_address("127.0.0.1"), port}, asio::use_awaitable);
            co_await asio::async_write(sock, asio::buffer(request), asio::use_awaitable);
            sock.shutdown(asio::ip::tcp::socket::shutdown_send);
            auto [got, ec] = co_await read_to_end(sock);
            CHECK(got == response && ec == asio::error::eof,
                  "half-close: the peer receives the whole answer, then a clean end (not a reset)");
            CHECK(co_await wait_for(ctx, server_done), "half-close: the server side finished");
        });
}

// close() with unread data from the peer: the Connection ends its side and waits for
// the peer's end. Releasing the socket with unread data would make the kernel reset
// the connection and drop what is still in its send buffer; the answer is larger than
// the socket buffers and the peer starts reading late, so part of it is still queued
// when close() is called.
static void test_close_with_unread_data() {
    constexpr std::uint16_t port = 19997;
    const auto response = payload(6, 32u << 20);
    bool server_done = false;
    scenario(
        [&](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto l = co_await listen_tcp(ts, port);
            if (!l) co_return;
            auto ar = co_await l->accept();
            if (!ar) { ++g_failures; co_return; }
            auto conn = std::move(*ar);
            asio::steady_timer t(ctx, std::chrono::milliseconds(50));   // the peer's bytes arrive, unread
            co_await t.async_wait(asio::use_awaitable);
            co_await conn->send(make_message_view(std::span<const std::uint8_t>(response)));
            auto cr = co_await conn->close();
            CHECK(cr && conn->state() == ConnectionState::CLOSED,
                  "close with unread data: close() completes once the peer has ended, CLOSED");
            server_done = true;
        },
        [&](asio::io_context& ctx) -> asio::awaitable<void> {
            asio::ip::tcp::socket sock(ctx);
            co_await sock.async_connect({asio::ip::make_address("127.0.0.1"), port}, asio::use_awaitable);
            const auto unread = payload(7, 1000);
            co_await asio::async_write(sock, asio::buffer(unread), asio::use_awaitable);
            asio::steady_timer late(ctx, std::chrono::milliseconds(200));
            co_await late.async_wait(asio::use_awaitable);
            auto [got, ec] = co_await read_to_end(sock);
            asio::error_code ignored;
            sock.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
            CHECK(got.size() == response.size() && got == response && ec == asio::error::eof,
                  "close with unread data: the peer receives everything, then a clean end (not a reset)");
            if (got.size() != response.size() || ec != asio::error::eof)
                std::printf("      got %zu of %zu bytes, then %s\n", got.size(), response.size(), ec.message().c_str());
            CHECK(co_await wait_for(ctx, server_done), "close with unread data: the server side finished");
        });
}

// close() while a receive() is pending: the receive completes with INVALID_STATE.
static void test_close_with_pending_receive() {
    constexpr std::uint16_t port = 19998;
    scenario(
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            asio::ip::tcp::acceptor acc(ctx, {asio::ip::make_address("127.0.0.1"), port});
            auto sock = co_await acc.async_accept(asio::use_awaitable);
            auto [got, ec] = co_await read_to_end(sock);   // until the client's end
            sock.shutdown(asio::ip::tcp::socket::shutdown_send);
            (void)got; (void)ec;
        },
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto conn = co_await connect_tcp(ts, port);
            if (!conn) co_return;
            Connection* raw = conn.get();
            Result<void> closed = std::unexpected(TAPSError{ErrorEvent::CONNECTION_ERROR, ErrorReason::INTERNAL_ERROR, ""});
            bool close_done = false;
            asio::co_spawn(ctx, [&ctx, raw, &closed, &close_done]() -> asio::awaitable<void> {
                asio::steady_timer t(ctx, std::chrono::milliseconds(50));
                co_await t.async_wait(asio::use_awaitable);
                closed = co_await raw->close();
                close_done = true;
            }, asio::detached);
            auto rr = co_await conn->receive();
            CHECK(is_error(rr, ErrorEvent::RECEIVE_ERROR, ErrorReason::INVALID_STATE),
                  "close with a pending receive: the receive completes with RECEIVE_ERROR / INVALID_STATE");
            const bool finished = co_await wait_for(ctx, close_done);
            CHECK(finished && closed && conn->state() == ConnectionState::CLOSED,
                  "close with a pending receive: close() completes, CLOSED");
        });
}

// abort() resets the connection (RFC 9623 Section 10.1: ABORT.TCP sends a RST).
static void test_abort_resets() {
    constexpr std::uint16_t port = 19999;
    scenario(
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            TransportServices ts(ctx);
            auto l = co_await listen_tcp(ts, port);
            if (!l) co_return;
            auto ar = co_await l->accept();
            if (!ar) { ++g_failures; co_return; }
            co_await (*ar)->abort();
        },
        [](asio::io_context& ctx) -> asio::awaitable<void> {
            asio::ip::tcp::socket sock(ctx);
            co_await sock.async_connect({asio::ip::make_address("127.0.0.1"), port}, asio::use_awaitable);
            auto [got, ec] = co_await read_to_end(sock);
            CHECK(got.empty() && ec == asio::error::connection_reset, "abort: the peer sees a reset");
        });
}

// ---------------------------------------------------------------------------
// UDP Listener lifetime: passive Connections outlive their Listener, stop() only
// stops accepting new sources, and a source whose Connection is gone gets a new one
// (RFC 9623 Section 4.7.2).
// ---------------------------------------------------------------------------

// A plain UDP peer: sends one byte `b` to the listener.
static asio::awaitable<void> udp_send_byte(asio::ip::udp::socket& peer, std::uint16_t port, std::uint8_t b) {
    co_await peer.async_send_to(asio::buffer(&b, 1), {asio::ip::make_address("127.0.0.1"), port},
                                asio::use_awaitable);
}

static asio::awaitable<void> pause(asio::io_context& ctx, int ms) {
    asio::steady_timer t(ctx, std::chrono::milliseconds(ms));
    co_await t.async_wait(asio::use_awaitable);
}

static bool one_byte(const Result<Message>& r, std::uint8_t b) {
    return r && r->size() == 1 && std::to_integer<std::uint8_t>((*r->blocks().begin())[0]) == b;
}

static void test_udp_connection_outlives_listener() {
    constexpr std::uint16_t port = 19960;
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
        if (!lr) { CHECK(false, "udp outlives listener: listen"); co_return; }
        auto listener = std::move(*lr);
        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        co_await udp_send_byte(peer, port, 'a');
        auto ar = co_await listener->accept();
        if (!ar) { CHECK(false, "udp outlives listener: accept"); co_return; }
        auto conn = std::move(*ar);
        auto first = co_await conn->receive();

        listener.reset();                 // destroyed without stop(), receive loop pending
        co_await pause(ctx, 50);

        co_await udp_send_byte(peer, port, 'b');
        auto second = co_await conn->receive();
        CHECK(one_byte(first, 'a') && one_byte(second, 'b'),
              "udp: a passive connection keeps receiving after its Listener is destroyed");
        const std::uint8_t c = 'c';
        auto sr = co_await conn->send(make_message_view(std::span<const std::uint8_t>(&c, 1)));
        std::uint8_t got = 0;
        asio::ip::udp::endpoint from;
        auto [ec, n] = co_await peer.async_receive_from(asio::buffer(&got, 1), from,
                                                        asio::as_tuple(asio::use_awaitable));
        CHECK(sr && !ec && n == 1 && got == 'c',
              "udp: a passive connection keeps sending after its Listener is destroyed");
        co_await conn->close();
        co_await pause(ctx, 50);
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(10));
    check_finished(finished, "udp outlives listener test");
}

static void test_udp_listener_stop() {
    constexpr std::uint16_t port = 19961;
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
        if (!lr) { CHECK(false, "udp stop: listen"); co_return; }
        auto listener = std::move(*lr);
        asio::ip::udp::socket peer1(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        asio::ip::udp::socket peer2(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        co_await udp_send_byte(peer1, port, 'a');
        auto ar = co_await listener->accept();
        if (!ar) { CHECK(false, "udp stop: accept"); co_return; }
        auto conn = std::move(*ar);
        (void)co_await conn->receive();

        Result<std::unique_ptr<Connection>> pending =
            std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, "not run"});
        bool pending_done = false;
        Listener* raw = listener.get();
        asio::co_spawn(ctx, [raw, &pending, &pending_done]() -> asio::awaitable<void> {
            pending = co_await raw->accept();
            pending_done = true;
        }, fail_on_exception);
        co_await pause(ctx, 20);
        co_await listener->stop();
        co_await pause(ctx, 20);
        CHECK(pending_done && !pending && pending.error().event() == ErrorEvent::ESTABLISHMENT_ERROR &&
                  pending.error().reason() == ErrorReason::INVALID_STATE,
              "udp stop: a pending accept() completes with ESTABLISHMENT_ERROR / INVALID_STATE");

        co_await udp_send_byte(peer2, port, 'x');     // a new source: no new Connection
        co_await udp_send_byte(peer1, port, 'b');     // the existing source still delivers
        auto r = co_await conn->receive();
        CHECK(one_byte(r, 'b'), "udp stop: an existing connection keeps receiving after stop()");

        // The shared socket stays bound while a Connection uses it and is released
        // after the last one: a socket without SO_REUSEADDR can bind the port only then.
        auto can_bind = [&ctx] {
            asio::ip::udp::socket probe(ctx);
            asio::error_code ec;
            probe.open(asio::ip::udp::v4(), ec);
            probe.bind({asio::ip::make_address("127.0.0.1"), port}, ec);
            return !ec;
        };
        const bool bound_while_used = can_bind();
        co_await conn->close();
        co_await pause(ctx, 50);
        CHECK(!bound_while_used && can_bind(),
              "udp stop: the socket is released once the Listener has stopped and the last connection is closed");
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(10));
    check_finished(finished, "udp stop test");
}

static void test_udp_source_after_connection_destroyed() {
    constexpr std::uint16_t port = 19962;
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
        if (!lr) { CHECK(false, "udp new connection: listen"); co_return; }
        auto listener = std::move(*lr);
        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        co_await udp_send_byte(peer, port, 'a');
        {
            auto ar = co_await listener->accept();
            if (!ar) { CHECK(false, "udp new connection: first accept"); co_return; }
            (void)co_await (*ar)->receive();
        }                                              // destroyed without close()
        co_await pause(ctx, 20);
        co_await udp_send_byte(peer, port, 'b');
        Listener* raw = listener.get();
        Result<std::unique_ptr<Connection>> next =
            std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, "not run"});
        bool next_done = false;
        asio::co_spawn(ctx, [raw, &next, &next_done]() -> asio::awaitable<void> {
            next = co_await raw->accept();
            next_done = true;
        }, fail_on_exception);
        co_await pause(ctx, 300);
        bool second_ok = false;
        if (next_done && next) {
            auto r = co_await (*next)->receive();
            second_ok = one_byte(r, 'b');
            co_await (*next)->close();
        }
        CHECK(second_ok, "udp: after its Connection is destroyed, the same source gets a new Connection");
        co_await listener->stop();
        co_await pause(ctx, 50);
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(10));
    check_finished(finished, "udp new connection test");
}

// An active UDP Connection reserves its local port at initiate (RFC 9623 Section
// 10.3): it can receive before it has sent anything.
static void test_udp_receive_before_send() {
    constexpr std::uint16_t port = 19963;          // the peer's port; nothing listens on it
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port}, udp_props());
        auto cr = co_await pc.initiate();
        if (!cr) { CHECK(false, "udp receive before send: initiate"); co_return; }
        auto conn = std::move(*cr);
        const auto local = conn->get_local_endpoint();
        CHECK(conn->state() == ConnectionState::ESTABLISHED && local.port() != 0,
              "udp: initiate reserves a local port and the connection is ESTABLISHED");
        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), port));
        co_await udp_send_byte(peer, local.port(), 'r');
        auto r = co_await conn->receive();
        CHECK(one_byte(r, 'r'), "udp: an active connection receives before sending anything");
        co_await conn->close();
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(5));
    check_finished(finished, "udp receive before send test");
}

// A passive UDP Connection keeps the newest datagrams when its bounded queue
// fills (drop-oldest, counted), and delivers them in order.
static void test_udp_passive_queue_drops_oldest() {
    constexpr std::uint16_t port = 19964;
    constexpr std::uint16_t kSent = 300, kBound = 256;
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        TransportServices ts(ctx);
        auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, udp_props());
        if (!lr) { CHECK(false, "udp queue: listen"); co_return; }
        auto listener = std::move(*lr);
        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        for (std::uint16_t i = 0; i < kSent; ++i) {
            const std::uint8_t d[2] = {static_cast<std::uint8_t>(i >> 8), static_cast<std::uint8_t>(i)};
            co_await peer.async_send_to(asio::buffer(d), {asio::ip::make_address("127.0.0.1"), port},
                                        asio::use_awaitable);
            if (i % 50 == 49) co_await pause(ctx, 5);   // let the listener drain the socket
        }
        co_await pause(ctx, 50);
        auto ar = co_await listener->accept();
        if (!ar) { CHECK(false, "udp queue: accept"); co_return; }
        auto* passive = dynamic_cast<PassiveUDPConnection*>(ar->get());
        bool in_order = true;
        for (std::uint16_t expected = kSent - kBound; expected < kSent; ++expected) {
            auto r = co_await (*ar)->receive();
            const auto b = r ? r->as_bytes() : std::span<const std::byte>{};
            const std::uint16_t got = b.size() == 2
                ? static_cast<std::uint16_t>((std::to_integer<unsigned>(b[0]) << 8) | std::to_integer<unsigned>(b[1]))
                : 0xffff;
            in_order = in_order && got == expected;
        }
        CHECK(passive && passive->datagrams_dropped() == kSent - kBound && in_order,
              "udp: a full passive queue drops the oldest datagrams, counts them, and keeps the newest in order");
        co_await (*ar)->close();
        co_await listener->stop();
        co_await pause(ctx, 50);
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(10));
    check_finished(finished, "udp queue test");
}

// With several remote endpoints the protocol still follows the Selection
// Properties: an unreliable Preconnection gives a UDP Connection, established on the
// first endpoint (UDP has nothing to race).
static void test_udp_several_remote_endpoints() {
    constexpr std::uint16_t first = 19965, second = 19966;
    asio::io_context ctx;
    bool finished = false;
    asio::co_spawn(ctx, [&ctx, &finished]() -> asio::awaitable<void> {
        asio::ip::udp::socket peer(ctx, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), first));
        TransportServices ts(ctx);
        auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", first}, udp_props());
        pc.add_remote_endpoint(RemoteEndpoint{"127.0.0.1", second});
        auto cr = co_await pc.initiate();
        if (!cr) { CHECK(false, "udp several endpoints: initiate"); co_return; }
        const bool is_udp = dynamic_cast<ActiveUDPConnection*>(cr->get()) != nullptr;
        const std::uint8_t d = 'm';
        co_await (*cr)->send(make_message_view(std::span<const std::uint8_t>(&d, 1)));
        std::uint8_t got = 0;
        asio::ip::udp::endpoint from;
        auto [ec, n] = co_await peer.async_receive_from(asio::buffer(&got, 1), from,
                                                        asio::as_tuple(asio::use_awaitable));
        CHECK(is_udp && !ec && n == 1 && got == 'm',
              "udp: with several remote endpoints the connection is UDP, on the first endpoint");
        co_await (*cr)->close();
        finished = true;
    }, fail_on_exception);
    ctx.run_for(std::chrono::seconds(5));
    check_finished(finished, "udp several endpoints test");
}

int main() {
    test_unframed_stream();
    test_framed_records();
    test_framed_eof_inside_record();
    test_framed_eof_inside_header();
    test_framer_without_progress();
    test_whole_transfer(/*gather=*/true, 19983);
    test_whole_transfer(/*gather=*/false, 19984);
    test_whole_transfer_empty();
    test_echo(/*framed=*/false, 19985, "echo: an unframed received Message is sent back byte-exact");
    test_echo(/*framed=*/true, 19989, "echo: framed received Messages (up to 200000 bytes) are sent back byte-exact");
    test_pool_exhaustion();
    test_receive_interrupted_by_abort();
    test_reply_after_peer_end();
    test_close_with_unread_data();
    test_close_with_pending_receive();
    test_abort_resets();
    test_establishment_errors();
    test_udp_echo();
    test_udp_idle_eviction();
    test_udp_receive_before_send();
    test_udp_passive_queue_drops_oldest();
    test_udp_several_remote_endpoints();
    test_udp_connection_outlives_listener();
    test_udp_listener_stop();
    test_udp_source_after_connection_destroyed();

    if (g_failures == 0) {
        std::printf("connection_test: all checks passed\n");
        return 0;
    }
    std::printf("connection_test: %d check(s) failed\n", g_failures);
    return 1;
}
