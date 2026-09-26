# TAPS: Transport Services API for C++

A research-oriented C++ implementation of the IETF Transport Services (TAPS) architecture, as described in [RFC 9621](https://www.rfc-editor.org/rfc/rfc9621) and related RFCs. TAPS abstracts the underlying transport protocol (TCP, UDP, …) behind a unified, property-driven API built on top of Asio standalone coroutines.

## Features

- **Unified API** — send and receive `Message` objects without caring whether the socket underneath is TCP or UDP.
- **Transport property selection** — declare requirements such as reliability, ordering, and message boundaries; the library picks the appropriate protocol.
- **Happy Eyeballs racing** — concurrent connection attempts across multiple endpoints for faster establishment.
- **Pluggable message framers** — `NoOpFramer`, `LengthPrefixedFramer`, and `DelimiterFramer` included; implement `MessageFramer` to add your own.
- **C++20 coroutines** — async operations are expressed as `co_await` expressions on `asio::awaitable<>`.

## Requirements

| Dependency | Version |
|---|---|
| C++ compiler | GCC 14+ (C++23 required, but only because we are using std::expected) |
| CMake | 3.10+ |
| Asio standalone | any recent version (header-only) |

Asio standalone is available at <https://think-async.com/Asio/> or as part of the Boost distribution.

## Building

1. **Set the Asio path** — open [CMakeLists.txt](CMakeLists.txt) and update `ASIO_INCLUDE_DIR` to point to the directory that contains `asio.hpp`:

   ```cmake
   set(ASIO_INCLUDE_DIR "/path/to/asio/include" ...)
   ```

   Alternatively, pass it on the command line (see step 3).

2. **Create the build directory:**

   ```bash
   mkdir build && cd build
   ```

3. **Configure and build:**

   ```bash
   # Debug build
   cmake -DCMAKE_BUILD_TYPE=Debug ..

   # Release build
   cmake -DCMAKE_BUILD_TYPE=Release ..

   # Override ASIO path without editing CMakeLists.txt
   cmake -DCMAKE_BUILD_TYPE=Release -DASIO_INCLUDE_DIR=/path/to/asio/include ..

   make -j4
   ```

The static library is produced at `build/src/libtaps.a`. Example binaries are placed in `build/examples/`.

## Project structure

```
proyecto_taps/
├── include/taps/
│   ├── taps_api.h      # Public API — all classes and enums
│   └── mailbox.h       # Internal mailbox for UDP demultiplexing
├── src/                # Implementation files
│   ├── Connection.cpp
│   ├── Endpoint.cpp
│   ├── Preconnection.cpp
│   ├── TCPConnection.cpp
│   ├── TCPListener.cpp
│   ├── UDPConnection.cpp
│   ├── UDPListener.cpp
│   ├── TransportProperties.cpp
│   └── TransportServices.cpp
└── examples/
    ├── tcpclient/      # TCP client example
    ├── tcpserver/      # TCP server example
    ├── udpclient/      # UDP client example
    └── udpserver/      # UDP server example
```

## Quick start

### TCP client

```cpp
#include "taps/taps_api.h"
#include <asio.hpp>

int main() {
    asio::io_context ctx;

    auto run = [&]() -> asio::awaitable<void> {
        taps::TransportServices ts(ctx);

        taps::TransportProperties props;
        props.set(taps::PropertyKey::RELIABILITY, taps::SelectionProperty::REQUIRE);

        auto preconn = ts.preconnect(
            taps::LocalEndpoint{},
            taps::RemoteEndpoint{"localhost", 9999},
            std::move(props)
        );

        auto conn_result = co_await preconn.initiate();
        if (!conn_result) { co_return; }
        auto& conn = *conn_result;

        co_await conn->send(taps::make_message_view("Hello, TAPS!"));
        auto msg = co_await conn->receive();
        co_await conn->close();
    };

    co_spawn(ctx, run(), asio::detached);
    ctx.run();
}
```

### UDP server

```cpp
#include "taps/taps_api.h"
#include <asio.hpp>

int main() {
    asio::io_context ctx;

    auto run = [&]() -> asio::awaitable<void> {
        taps::TransportServices ts(ctx);

        taps::TransportProperties props;
        props.set(taps::PropertyKey::RELIABILITY, taps::SelectionProperty::AVOID);

        auto listener_result = co_await ts.listen(
            taps::LocalEndpoint{"0.0.0.0", 9999},
            std::move(props)
        );
        auto& listener = *listener_result;
        co_await listener->listen();

        while (true) {
            auto conn_result = co_await listener->accept();
            auto& conn = *conn_result;
            auto msg = co_await conn->receive();
            co_await conn->send(taps::make_message_view("Echo!"));
            co_await conn->close();
        }
    };

    co_spawn(ctx, run(), asio::detached);
    ctx.run();
}
```

See the [examples/](examples/) directory for complete, buildable programs.

## Transport properties

| `PropertyKey` | Effect |
|---|---|
| `RELIABILITY` | REQUIRE → TCP; AVOID → UDP |
| `PRESERVE_ORDER` | Ordered delivery |
| `PRESERVE_MSG_BOUNDARIES` | Datagram semantics |
| `CONGESTION_CONTROL` | Congestion-controlled transport |
| `DIRECTION` | Unidirectional send/receive or bidirectional |

Values: `REQUIRE`, `PREFER`, `IGNORE`, `AVOID`, `PROHIBIT`.

## Message framers

| Class | Description |
|---|---|
| `NoOpFramer` | Passes raw bytes through unchanged |
| `LengthPrefixedFramer` | Prefixes each message with a fixed-size length field (configurable width and byte order) |
| `DelimiterFramer` | Splits the stream at a byte sequence delimiter |

Assign a framer to a connection with `conn->set_framer(std::make_unique<MyFramer>(...))`.

## Known limitations

- **One Connection, one thread at a time.** The operations of a Connection must not
  run concurrently on different threads: use a single-threaded `io_context`, one
  chain of operations per Connection, or one strand for every coroutine that uses it.
  Over TLS this includes full duplex (receiving and sending from two coroutines on
  different threads), because both directions share one TLS session. A concurrency
  model of the library's own, independent of the asynchronous backend, is future work.
- **`Message::as_bytes()` is not `const`.** For a received Message spread over several
  blocks it copies the payload, on the first call, into a buffer the Message keeps;
  two threads must not call it on the same Message at once. `Message::blocks()` and
  `taps::gather()` read a Message without that copy and are `const`.
- **Protocol selection and racing** (RFC 9623 Section 4): the protocol is TCP when
  reliability is required or preferred, UDP otherwise; candidates are not gathered and
  raced across protocol stacks. Racing (RFC 9623 Section 4.3, RFC 8305) covers the
  addresses of TCP's remote endpoints, one attempt after another rather than staggered
  attempts that overlap.
- **Security**: the only security protocol is TLS over TCP. RFC 9621 does not tie the
  Security Parameters to a protocol; security for datagrams (e.g. DTLS) or integrated
  in the transport (e.g. QUIC) is not available, and requesting security over UDP
  fails with `NO_CANDIDATES`.
- **UDP soft errors** (RFC 9623 Section 10.3): not yet implemented. ICMP errors such as
  "port unreachable" are not reported as `SoftError` events; on the unconnected sockets
  used for UDP they are not seen at all.
- **Connections from one UDP Listener share its socket**, and send on it from any thread
  while the Listener receives. asio guarantees concurrent use of one socket object only
  for synchronous operations; taps_cpp relies on the Linux epoll backend, which locks
  each socket's asynchronous operation queues.
- **Passive UDP on a multi-threaded `io_context`.** A UDP Listener receives on one strand,
  which it shares with the receive queues of all its Connections. Receivers resuming on
  other threads compete for that strand, and under a sustained stream of incoming
  datagrams the Listener falls behind and the kernel drops datagrams; on a
  single-threaded `io_context` it keeps up. Sending is not affected. Reducing this
  contention is future work.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgements

Special thanks to Jose Carlos Sequera-Montes and Jose Antonio García-Montañéz for their contributions to the project and for their support during its development.
