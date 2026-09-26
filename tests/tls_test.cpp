// End-to-end TLS over the taps_cpp public API only: a taps_cpp listener with a
// server certificate and a taps_cpp client with the pinned CA, exercising the
// no-framer, framed and bulk paths over the encrypted stream, plus negative cases:
// a wrong trust anchor is rejected without stopping the Listener, and a stream
// truncated without close_notify ends in a ReceiveError; and the close sequence:
// half-close (answer after the peer's close_notify) and close() with a pending
// receive(). Certificates are generated into the
// build directory by gen_test_certs.sh; TLS_TEST_CERT_DIR points at them.

#include "taps/taps_api.h"
#include "taps/message_framer.h"

#include <asio.hpp>

#include <chrono>
#include <cstdio>
#include <exception>
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

// Completion handler for spawned coroutines: an escaping exception is a failure.
static void fail_on_exception(std::exception_ptr e) {
    if (!e) return;
    try { std::rethrow_exception(e); }
    catch (const std::exception& x) { std::printf("FAIL  coroutine threw: %s\n", x.what()); }
    ++g_failures;
}

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

// Server that sends and then drops the connection without close(): the socket closes
// without a TLS close_notify.
static constexpr std::size_t DROP_BYTES = 64u * 1024;

static asio::awaitable<void> drop_server(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { ++g_failures; co_return; }
    auto ar = co_await (*lr)->accept();
    if (!ar) { ++g_failures; co_return; }
    auto conn = std::move(*ar);
    std::vector<std::uint8_t> buf(DROP_BYTES, 0x5a);
    co_await conn->send(make_message_view(buf));
}

static asio::awaitable<void> truncation_client(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    if (!cr) { std::printf("FAIL  truncation: initiate: %s\n", cr.error().message().c_str()); ++g_failures; co_return; }
    auto& conn = *cr;
    std::size_t total = 0;
    Result<Message> rr = std::unexpected(TAPSError{ErrorEvent::RECEIVE_ERROR, ErrorReason::INTERNAL_ERROR, ""});
    for (;;) {
        rr = co_await conn->receive();
        if (!rr || rr->size() == 0) break;
        total += rr->size();
    }
    CHECK(total == DROP_BYTES && !rr && rr.error().event() == ErrorEvent::RECEIVE_ERROR &&
              rr.error().reason() == ErrorReason::PROTOCOL_FAILED,
          "peer closing without close_notify: the data, then RECEIVE_ERROR / PROTOCOL_FAILED");
    CHECK(conn->state() == ConnectionState::ESTABLISHED && !conn->can_receive(),
          "truncated TLS stream: nothing more to receive, the connection is not closed by it");
}

// TLS half-close: the client sends a request and closes (close_notify, then waits
// for the server's end); the server receives the request to its end, can still send
// (RFC 9623 Section 10.1), answers, and closes. The answer arrives after the client's
// close_notify, so the client discards it (RFC 9622 Section 10); both close() calls
// complete.
static bool g_half_server_done = false;

static asio::awaitable<void> half_close_server(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { ++g_failures; co_return; }
    auto ar = co_await (*lr)->accept();
    if (!ar) { ++g_failures; co_return; }
    auto conn = std::move(*ar);
    std::size_t got = 0;
    bool ended = false;
    for (;;) {
        auto rr = co_await conn->receive();
        if (!rr) break;
        got += rr->size();
        if (rr->is_end_of_message()) { ended = true; break; }
    }
    CHECK(ended && got == 1000 && conn->can_send() && !conn->can_receive(),
          "TLS half-close: the server receives the request to its end and can still send");
    std::vector<std::uint8_t> answer(256u * 1024, 0x42);
    auto sr = co_await conn->send(make_message_view(answer));
    CHECK(static_cast<bool>(sr), "TLS half-close: send() after the peer's close_notify succeeds");
    auto cr = co_await conn->close();
    CHECK(cr && conn->state() == ConnectionState::CLOSED, "TLS half-close: the server's close() completes");
    g_half_server_done = true;
}

static asio::awaitable<void> half_close_client(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    if (!cr) { ++g_failures; co_return; }
    auto& conn = *cr;
    std::vector<std::uint8_t> request(1000, 0x21);
    co_await conn->send(make_message_view(request));
    auto closed = co_await conn->close();
    CHECK(closed && conn->state() == ConnectionState::CLOSED,
          "TLS half-close: the client's close() completes after discarding the answer");
    for (int i = 0; i < 100 && !g_half_server_done; ++i) {
        asio::steady_timer t(ctx, std::chrono::milliseconds(10));
        co_await t.async_wait(asio::use_awaitable);
    }
    CHECK(g_half_server_done, "TLS half-close: the server side finished");
}

// close() while a receive() is pending on a TLS connection.
static asio::awaitable<void> end_after_peer_server(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { ++g_failures; co_return; }
    auto ar = co_await (*lr)->accept();
    if (!ar) { ++g_failures; co_return; }
    auto conn = std::move(*ar);
    for (;;) {
        auto rr = co_await conn->receive();
        if (!rr || rr->is_end_of_message()) break;
    }
    co_await conn->close();
}

static asio::awaitable<void> pending_receive_client(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    if (!cr) { ++g_failures; co_return; }
    Connection* raw = cr->get();
    bool close_done = false;
    Result<void> closed = std::unexpected(TAPSError{ErrorEvent::CONNECTION_ERROR, ErrorReason::INTERNAL_ERROR, ""});
    asio::co_spawn(ctx, [&ctx, raw, &closed, &close_done]() -> asio::awaitable<void> {
        asio::steady_timer t(ctx, std::chrono::milliseconds(50));
        co_await t.async_wait(asio::use_awaitable);
        closed = co_await raw->close();
        close_done = true;
    }, asio::detached);
    auto rr = co_await (*cr)->receive();
    CHECK(!rr && rr.error().event() == ErrorEvent::RECEIVE_ERROR &&
              rr.error().reason() == ErrorReason::INVALID_STATE,
          "TLS close with a pending receive: the receive completes with RECEIVE_ERROR / INVALID_STATE");
    for (int i = 0; i < 100 && !close_done; ++i) {
        asio::steady_timer t(ctx, std::chrono::milliseconds(10));
        co_await t.async_wait(asio::use_awaitable);
    }
    CHECK(close_done && closed && raw->state() == ConnectionState::CLOSED,
          "TLS close with a pending receive: close() completes, CLOSED");
}

// Handshakes of concurrent clients run in parallel: a client that connects and
// never starts its handshake does not hold back the next one.
static asio::awaitable<void> parallel_handshake_server(asio::io_context& ctx, std::uint16_t port,
                                                       bool& accepted_second) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { ++g_failures; co_return; }
    auto ar = co_await (*lr)->accept();
    accepted_second = static_cast<bool>(ar);
    if (ar) {
        auto rr = co_await (*ar)->receive();
        if (rr) co_await (*ar)->send(*rr);
        co_await (*ar)->close();
    }
}

static asio::awaitable<void> parallel_handshake_client(asio::io_context& ctx, std::uint16_t port,
                                                       const bool& accepted_second) {
    asio::ip::tcp::socket stalled(ctx);                  // connects, never handshakes
    co_await stalled.async_connect({asio::ip::make_address("127.0.0.1"), port}, asio::use_awaitable);
    asio::steady_timer t(ctx, std::chrono::milliseconds(50));
    co_await t.async_wait(asio::use_awaitable);

    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    bool echoed = false;
    if (cr) {
        const std::string hello = "hello";
        co_await (*cr)->send(make_message_view(hello));
        auto rr = co_await (*cr)->receive();
        echoed = rr && rr->size() == hello.size();
        co_await (*cr)->close();
    }
    CHECK(cr && echoed && accepted_second,
          "TLS listener: a stalled handshake does not hold back the next client");
    stalled.close();
}

// A TLS configuration the Listener cannot fulfil fails listen(), not a later accept().
static asio::awaitable<void> bad_config_listen(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    SecurityParameters sp = server_params();
    sp.set_certificate_chain_file(path("does-not-exist.crt"));
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), sp);
    CHECK(!lr && lr.error().event() == ErrorEvent::ESTABLISHMENT_ERROR &&
              lr.error().reason() == ErrorReason::INVALID_CONFIGURATION,
          "TLS listener: a bad certificate fails listen() with ESTABLISHMENT_ERROR / INVALID_CONFIGURATION");
}

// stop() makes a pending accept() fail; the Listener can then be destroyed with a
// handshake still in flight.
static asio::awaitable<void> stop_with_pending_accept(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", port}, tcp_props(), server_params());
    if (!lr) { ++g_failures; co_return; }
    auto listener = std::move(*lr);
    asio::ip::tcp::socket stalled(ctx);                  // a handshake that will be in flight
    co_await stalled.async_connect({asio::ip::make_address("127.0.0.1"), port}, asio::use_awaitable);

    Listener* raw = listener.get();
    Result<std::unique_ptr<Connection>> pending =
        std::unexpected(TAPSError{ErrorEvent::ESTABLISHMENT_ERROR, ErrorReason::INTERNAL_ERROR, "not run"});
    bool pending_done = false;
    asio::co_spawn(ctx, [raw, &pending, &pending_done]() -> asio::awaitable<void> {
        pending = co_await raw->accept();
        pending_done = true;
    }, fail_on_exception);
    asio::steady_timer t(ctx, std::chrono::milliseconds(50));
    co_await t.async_wait(asio::use_awaitable);
    co_await listener->stop();
    t.expires_after(std::chrono::milliseconds(50));
    co_await t.async_wait(asio::use_awaitable);
    CHECK(pending_done && !pending && pending.error().event() == ErrorEvent::ESTABLISHMENT_ERROR &&
              pending.error().reason() == ErrorReason::INVALID_STATE,
          "TLS listener: stop() makes a pending accept() fail with ESTABLISHMENT_ERROR / INVALID_STATE");
    listener.reset();                                    // handshake still in flight
    stalled.close();                                     // it fails now, after the Listener is gone
    t.expires_after(std::chrono::milliseconds(100));
    co_await t.async_wait(asio::use_awaitable);
}

// Security requested over UDP (no security protocol for datagrams here) is an
// EstablishmentError, not plaintext.
static TransportProperties udp_props() {
    TransportProperties p;
    p.set(PropertyKey::RELIABILITY, SelectionProperty::AVOID);
    return p;
}

static asio::awaitable<void> udp_with_security(asio::io_context& ctx) {
    TransportServices ts(ctx);
    auto lr = co_await ts.listen(LocalEndpoint{"127.0.0.1", 19969}, udp_props(), server_params());
    CHECK(!lr && lr.error().event() == ErrorEvent::ESTABLISHMENT_ERROR &&
              lr.error().reason() == ErrorReason::NO_CANDIDATES,
          "UDP listen with security: ESTABLISHMENT_ERROR / NO_CANDIDATES");
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", 19969},
                            udp_props(), client_params(path("ca.crt")));
    auto cr = co_await pc.initiate();
    CHECK(!cr && cr.error().event() == ErrorEvent::ESTABLISHMENT_ERROR &&
              cr.error().reason() == ErrorReason::NO_CANDIDATES,
          "UDP initiate with security: ESTABLISHMENT_ERROR / NO_CANDIDATES");
}

// Client that pins the wrong anchor (the leaf itself) must fail the handshake.
static asio::awaitable<void> bad_anchor_client(asio::io_context& ctx, std::uint16_t port) {
    TransportServices ts(ctx);
    auto pc = ts.preconnect(LocalEndpoint{}, RemoteEndpoint{"127.0.0.1", port},
                            tcp_props(), client_params(path("srv.crt")));
    auto cr = co_await pc.initiate();
    CHECK(!cr && cr.error().event() == ErrorEvent::ESTABLISHMENT_ERROR &&
              cr.error().reason() == ErrorReason::ESTABLISHMENT_FAILED,
          "wrong trust anchor is rejected: ESTABLISHMENT_ERROR / ESTABLISHMENT_FAILED");
}


// Set by each scenario's client when it reaches its end.
static bool g_client_done = false;

// Runs `setup` on a fresh io_context until it stops; a client that never reaches
// its end is a failure.
template <typename Setup>
static void scenario(Setup setup) {
    asio::io_context ctx;
    g_client_done = false;
    setup(ctx);
    ctx.run();
    if (!g_client_done) {
        std::printf("FAIL  scenario: the client side did not finish\n");
        ++g_failures;
    }
}

int main() {
    scenario([](asio::io_context& c) {
        co_spawn(c, echo_server(c, 19970, false), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await echo_client(c, 19970, false, "no-framer echo over TLS");
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, echo_server(c, 19971, true), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await echo_client(c, 19971, true, "framed echo over TLS");
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, bulk_server(c, 19972), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await bulk_client(c, 19972);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, echo_server(c, 19973, false), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await bad_anchor_client(c, 19973);
            // The failed handshake is not a Listener error: the same accept() goes
            // on to deliver the next, valid connection.
            co_await echo_client(c, 19973, false, "listener keeps accepting after a failed handshake");
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, drop_server(c, 19974), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await truncation_client(c, 19974);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });

    scenario([](asio::io_context& c) {
        co_spawn(c, half_close_server(c, 19975), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await half_close_client(c, 19975);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, end_after_peer_server(c, 19976), fail_on_exception);
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            asio::steady_timer t(c, std::chrono::milliseconds(150));
            co_await t.async_wait(asio::use_awaitable);
            co_await pending_receive_client(c, 19976);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });

    {
        bool accepted_second = false;
        scenario([&accepted_second](asio::io_context& c) {
            co_spawn(c, parallel_handshake_server(c, 19977, accepted_second), fail_on_exception);
            co_spawn(c, [&c]() -> asio::awaitable<void> {     // serialised handshakes would hang
                asio::steady_timer watchdog(c, std::chrono::seconds(5));
                co_await watchdog.async_wait(asio::use_awaitable);
                c.stop();
            }, fail_on_exception);
            co_spawn(c, [&c, &accepted_second]() -> asio::awaitable<void> {
                asio::steady_timer t(c, std::chrono::milliseconds(150));
                co_await t.async_wait(asio::use_awaitable);
                co_await parallel_handshake_client(c, 19977, accepted_second);
                g_client_done = true;
                c.stop();
            }, fail_on_exception);
        });
    }
    scenario([](asio::io_context& c) {
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            co_await bad_config_listen(c, 19978);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });
    scenario([](asio::io_context& c) {
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            co_await stop_with_pending_accept(c, 19979);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });

    scenario([](asio::io_context& c) {
        co_spawn(c, [&c]() -> asio::awaitable<void> {
            co_await udp_with_security(c);
            g_client_done = true;
            c.stop();
        }, fail_on_exception);
    });

    if (g_failures == 0) {
        std::printf("tls_test: all checks passed\n");
        return 0;
    }
    std::printf("tls_test: %d check(s) failed\n", g_failures);
    return 1;
}
