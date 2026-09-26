// ConstBufferSequence: what one send() puts on the wire (optional framing header,
// then a contiguous body or the blocks of a chain), consumed by asio as a buffer
// sequence. Checked at compile time as an asio ConstBufferSequence for plain and TLS
// writes, and at run time byte for byte through asio::write over a socket pair.

#include "transport/const_buffer_sequence.h"
#include "buffer/message_block_pool.h"
#include "taps/taps_api.h"

#include <asio.hpp>
#include <asio/local/connect_pair.hpp>
#ifdef TAPS_WITH_TLS
#include <asio/ssl.hpp>
#endif

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <span>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

using namespace taps;

static int g_failures = 0;
#define CHECK(cond, name)                                                       \
    do {                                                                       \
        if (cond) { std::printf("PASS  %s\n", name); }                         \
        else { std::printf("FAIL  %s  (%s:%d)\n", name, __FILE__, __LINE__); ++g_failures; } \
    } while (0)

using IoAwaitable = asio::awaitable<std::tuple<asio::error_code, std::size_t>>;

static_assert(std::forward_iterator<ConstBufferSequence::const_iterator>);
static_assert(asio::is_const_buffer_sequence<ConstBufferSequence>::value);
static_assert(std::is_same_v<decltype(asio::async_write(std::declval<asio::ip::tcp::socket&>(),
    std::declval<const ConstBufferSequence&>(), asio::as_tuple(asio::use_awaitable))), IoAwaitable>);
#ifdef TAPS_WITH_TLS
static_assert(std::is_same_v<decltype(asio::async_write(
    std::declval<asio::ssl::stream<asio::ip::tcp::socket&>&>(),
    std::declval<const ConstBufferSequence&>(), asio::as_tuple(asio::use_awaitable))), IoAwaitable>);
#endif

static std::span<const std::byte> bytes(const std::string& s) { return std::as_bytes(std::span(s)); }

// Writes the sequence through asio and reads back exactly what went on the wire.
static bool roundtrip(const ConstBufferSequence& seq, const std::string& expected) {
    asio::io_context io;
    asio::local::stream_protocol::socket a(io), b(io);
    asio::local::connect_pair(a, b);
    const std::size_t sent = asio::write(a, seq);
    std::string got(expected.size(), '\0');
    asio::read(b, asio::buffer(got));
    return sent == expected.size() && got == expected && asio::buffer_size(seq) == expected.size();
}

// A chain whose blocks hold `parts`, one block per part.
static BlockChain chain_of(MessageBlockPool& pool, std::initializer_list<std::string> parts) {
    BlockChain chain;
    for (const std::string& p : parts) {
        BlockRef r = pool.acquire();
        std::memcpy(r.writable_data(), p.data(), p.size());
        r.set_range(0, p.size());
        chain.append(std::move(r));
    }
    return chain;
}

int main() {
    MessageMemoryConfig memory;
    memory.block_size = 64;
    MessageBlockPool pool(memory);
    const std::string hdr = "HDR:", body = "contiguous-body", b1 = "block-one|", b2 = "block-two|", b3 = "three";
    const BlockChain chain = chain_of(pool, {b1, b2, b3});
    const BlockChain empty_chain;

    CHECK(roundtrip({bytes(hdr), bytes(body)}, hdr + body), "header + contiguous body arrive byte-exact");
    CHECK(roundtrip({{}, bytes(body)}, body), "contiguous body alone arrives byte-exact");
    CHECK(roundtrip({bytes(hdr), chain}, hdr + b1 + b2 + b3), "header + chain arrive byte-exact");
    CHECK(roundtrip({{}, chain}, b1 + b2 + b3), "chain alone arrives byte-exact");
    CHECK(roundtrip({bytes(hdr), empty_chain}, hdr), "header + empty chain is the header alone");

    // From a Message, as it is: an owning Message, a view, a received (chain) one.
    const std::string text = "owning-message";
    const Message owning(std::vector<std::uint8_t>(text.begin(), text.end()));
    const Message view = make_message_view(body);
    const Message received(std::make_shared<BlockChain>(chain_of(pool, {b1, b2, b3})));
    CHECK(roundtrip({bytes(hdr), owning}, hdr + text), "header + owning Message arrive byte-exact");
    CHECK(roundtrip({{}, view}, body), "a view Message arrives byte-exact");
    CHECK(roundtrip({bytes(hdr), received}, hdr + b1 + b2 + b3), "header + received Message arrive byte-exact, from its blocks");

    const ConstBufferSequence seq(bytes(hdr), chain);
    CHECK(std::distance(seq.begin(), seq.end()) == 4, "one buffer per non-empty part: header and three blocks");
    const ConstBufferSequence nothing({}, empty_chain);
    CHECK(nothing.begin() == nothing.end(), "an empty sequence yields no buffer");

    if (g_failures == 0) {
        std::printf("const_buffer_sequence_test: all checks passed\n");
        return 0;
    }
    std::printf("const_buffer_sequence_test: %d check(s) failed\n", g_failures);
    return 1;
}
