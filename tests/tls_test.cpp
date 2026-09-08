// End-to-end TLS over the taps_cpp public API only: a taps_cpp listener with a
// server certificate and a taps_cpp client with the pinned CA, exercising the
// no-framer, framed and bulk paths over the encrypted stream, plus a negative
// case (wrong trust anchor must be rejected). Certificates are generated into the
// build directory by gen_test_certs.sh; TLS_TEST_CERT_DIR points at them.

#include "taps/taps_api.h"
#include "taps/message_framer.h"

#include <asio.hpp>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace taps;

#ifndef TLS_TEST_CERT_DIR
#error "TLS_TEST_CERT_DIR must be defined by the build"
#endif

static int g_failures = 0;
#define CHECK(cond, name)                                                       \
    do {                                                                       \
        if (cond) { std::printf("PASS  %s\n", name); }                         \
        else { std::printf("FAIL  %s  (%s:%d)\n", name, __FILE__, __LINE__); ++g_failures; } \
    } while (0)

static std::string path(const char* f) { return std::string(TLS_TEST_CERT_DIR) + "/" + f; }

static TransportProperties tcp_props() {
    TransportProperties p;
    p.set(PropertyKey::RELIABILITY, SelectionProperty::REQUIRE);
    return p;
}

static SecurityParameters server_params() {
    SecurityParameters sp;
    sp.require_tls();
    sp.set_tls_version_range(TLSVersion::TLS_1_3, TLSVersion::TLS_1_3);
    sp.set_certificate_chain_file(path("srv.crt"));
    sp.set_private_key_file(path("srv.key"));
    sp.add_alpn("taps-test/1");
    sp.set_ciphersuites({"TLS_AES_128_GCM_SHA256"});
    sp.set_supported_groups({"X25519"});
    return sp;
}

static SecurityParameters client_params(const std::string& ca) {
    SecurityParameters sp;
    sp.require_tls();
    sp.set_tls_version_range(TLSVersion::TLS_1_3, TLSVersion::TLS_1_3);
    sp.add_trust_anchor(ca);
    sp.set_server_name("localhost");
    sp.add_alpn("taps-test/1");
    sp.set_ciphersuites({"TLS_AES_128_GCM_SHA256"});
    sp.set_supported_groups({"X25519"});
    return sp;
}

// One echoing server accept; `framed` toggles the LengthPrefixedFramer.
static asio::awaitable<void> echo_server(asio::io_context& ctx, std::uint16_t port, bool framed) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { std::printf("FAIL  server listen: %s\n", lr.error().message().c_str()); ++g_failures; co_return; }
    auto ar = co_await (*lr)->accept();
    if (!ar) { std::printf("FAIL  server accept: %s\n", ar.error().message().c_str()); ++g_failures; co_return; }
    auto conn = std::move(*ar);
    if (framed) conn->set_framer(std::make_unique<LengthPrefixedFramer>());
    for (;;) {
        auto rr = co_await conn->receive();
        if (!rr) break;
        auto m = std::move(*rr);
        if (m.is_end_of_message() && m.size() == 0) break;
        if (!(co_await conn->send(m))) break;
        if (!framed) break;
    }
    co_await conn->close();
}

static asio::awaitable<void> echo_client(asio::io_context& ctx, std::uint16_t port, bool framed,
                                         const char* name) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    if (!cr) { std::printf("FAIL  %s: initiate: %s\n", name, cr.error().message().c_str()); ++g_failures; co_return; }
    auto& conn = *cr;
    if (framed) conn->set_framer(std::make_unique<LengthPrefixedFramer>());

    std::vector<std::string> msgs = framed
        ? std::vector<std::string>{"first", std::string(8192, 'k'), "last"}
        : std::vector<std::string>{"one contiguous encrypted message"};
    int exact = 0;
    for (const auto& s : msgs) {
        if (!(co_await conn->send(make_message_view(s)))) break;
        auto rr = co_await conn->receive();
        if (!rr) break;
        auto m = std::move(*rr);
        auto b = m.as_bytes();
        if (std::string(reinterpret_cast<const char*>(b.data()), b.size()) == s) ++exact;
    }
    CHECK(exact == static_cast<int>(msgs.size()), name);
    co_await conn->close();
}

static constexpr std::size_t BULK = 32u * 1024 * 1024;

static asio::awaitable<void> bulk_server(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { ++g_failures; co_return; }
    auto ar = co_await (*lr)->accept();
    if (!ar) { ++g_failures; co_return; }
    auto conn = std::move(*ar);
    std::vector<std::uint8_t> buf(BULK, 0xa5);
    co_await conn->send(make_message_view(buf));
    co_await conn->close();
}

static asio::awaitable<void> bulk_client(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    if (!cr) { std::printf("FAIL  bulk: initiate: %s\n", cr.error().message().c_str()); ++g_failures; co_return; }
    auto& conn = *cr;
    std::size_t total = 0;
    for (;;) {
        auto rr = co_await conn->receive();
        if (!rr) { ++g_failures; break; }
        auto m = std::move(*rr);
        total += m.size();
        if (m.is_end_of_message()) break;
    }
    CHECK(total == BULK, "bulk transfer over TLS");
    co_await conn->close();
}

// Client that pins the wrong anchor (the leaf itself) must fail the handshake.
static asio::awaitable<void> bad_anchor_client(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("srv.crt")));
    auto cr = co_await pc.initiate();
    CHECK(!cr, "wrong trust anchor is rejected");
}

// Runs `setup` on a fresh io_context until it stops.
template <typename Setup>
static void scenario(Setup setup) {
    asio::io_context ctx;
    setup(ctx);
    ctx.run();
}

int main() {
    scenario([](asio::io_context& c) {
        co_spawn(c, echo_server(c, 19970, false), asio::detached);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await echo_client(c, 19970, false, "no-framer echo over TLS");
            c.stop();
        }, asio::detached);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, echo_server(c, 19971, true), asio::detached);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await echo_client(c, 19971, true, "framed echo over TLS");
            c.stop();
        }, asio::detached);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, bulk_server(c, 19972), asio::detached);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await bulk_client(c, 19972);
            c.stop();
        }, asio::detached);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, echo_server(c, 19973, false), asio::detached);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await bad_anchor_client(c, 19973);
            c.stop();
        }, asio::detached);
    });

    if (g_failures == 0) {
        std::printf("tls_test: all checks passed\n");
        return 0;
    }
    std::printf("tls_test: %d check(s) failed\n", g_failures);
    return 1;
}
