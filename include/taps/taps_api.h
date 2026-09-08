#pragma once

#include <asio/awaitable.hpp>
#include <asio/strand.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/experimental/channel.hpp>

#include "taps/message_framer.h"   // taps::MessageFramer (API v2), ReceiveCursor, ParseResult

#include <string>
#include <vector>
#include <map>
#include <list>
#include <memory>
#include <functional>
#include <chrono>
#include <cstddef>
#include <span>
#include <expected>
#include <unordered_map>
#include <bit>

namespace taps {

// Forward declarations
class Message;
class MessageContext;
class MessageFramer;
class BlockChain;  // src/buffer/block_chain.h — receive-path substrate (private)
class BlockPool;   // src/buffer/block_pool.h  — receive-path substrate (private)
class BlockRef;    // src/buffer/block.h       — receive-path substrate (private)
class BlockPoolFactory;
class ByteStream;        // src/transport/byte_stream.h — I/O transport (plain socket or TLS)
class SecurityProvider;  // src/security/security_provider.h — applies TLS at establishment
class Connection;
class TCPConnection;
class Listener;
class Preconnection;
class TransportProperties;
class SecurityParameters;
class LocalEndpoint;
class RemoteEndpoint;
class Mailbox;

// ============================================================================
// Error Handling
// ============================================================================

enum class ErrorType {
    CONNECTION_FAILED,
    CONNECTION_REFUSED,
    CONNECTION_TIMEOUT,
    INTERNAL_ERROR,
    INSUFFICIENT_DATA,
    INVALID_CONFIGURATION,
    RESOLUTION_FAILED,
    FRAMING_ERROR,
    PROTOCOL_ERROR
};

class TAPSError {
public:
    TAPSError(ErrorType type, std::string message) 
        : type_(type), message_(std::move(message)) {}
    
    ErrorType type() const noexcept { return type_; }
    const std::string& message() const noexcept { return message_; }

private:
    ErrorType type_;
    std::string message_;
};

template<typename T>
using Result = std::expected<T, TAPSError>;

// ============================================================================
// Transport Properties
// ============================================================================

enum class SelectionProperty {
    REQUIRE,
    PREFER,
    IGNORE,
    AVOID,
    PROHIBIT
};

enum class PropertyKey {
    RELIABILITY,
    PRESERVE_ORDER,
    PRESERVE_MSG_BOUNDARIES,
    PER_MSG_RELIABILITY,
    PRESERVE_DATA,
    CONGESTION_CONTROL,
    KEEP_ALIVE,
    INTERFACE_INSTANCE,
    DIRECTION,
    MULTIPATH,
    CHECKSUM_COVERAGE_SEND,
    CHECKSUM_COVERAGE_RECEIVE
};

enum class Direction {
    UNIDIRECTIONAL_SEND,
    UNIDIRECTIONAL_RECEIVE,
    BIDIRECTIONAL
};

class TransportProperties {
public:
    void set(PropertyKey key, SelectionProperty value) {
        properties_[key] = value;
    }
    
    SelectionProperty get(PropertyKey key) const {
        if (auto it = properties_.find(key); it != properties_.end()) {
            return it->second;
        }
        return SelectionProperty::IGNORE;
    }
    
    bool requires_reliable_transport() const noexcept;
    bool requires_ordered_delivery() const noexcept;
    bool requires_message_boundaries() const noexcept;
    Direction get_direction() const noexcept;
    
    TransportProperties clone() const { return *this; }

private:
    std::map<PropertyKey, SelectionProperty> properties_;
};

// ============================================================================
// Security Parameters
// ============================================================================

enum class TLSVersion {
    TLS_1_2,
    TLS_1_3
};

// RFC 9622 Section 6.3.1 allowedSecurityProtocols. Only TLS is supported today;
// the enum leaves room for DTLS / others without an API break.
enum class SecurityProtocol {
    TLS
};

class SecurityParameters {
public:
    // Convenience: require TLS (the only protocol currently supported). Equivalent
    // to set_allowed_protocols({SecurityProtocol::TLS}). With no protocol set, a
    // Connection is established without security.
    void require_tls() {
        allowed_protocols_ = { SecurityProtocol::TLS };
    }

    // RFC 9622 Section 6.3.1. Empty (the default) means no security is requested.
    void set_allowed_protocols(std::vector<SecurityProtocol> protocols) {
        allowed_protocols_ = std::move(protocols);
    }

    void set_tls_version_range(TLSVersion min_version, TLSVersion max_version) {
        min_tls_version_ = min_version;
        max_tls_version_ = max_version;
    }

    // RFC 9622 Section 6.3.3. Path to a PEM file holding a trust anchor the peer
    // certificate is validated against. Repeatable.
    void add_trust_anchor(std::string ca_file_path) {
        trust_ca_.push_back(std::move(ca_file_path));
    }

    // Identity the peer certificate is validated against, also sent as SNI. When
    // unset, the remote endpoint hostname is used.
    void set_server_name(std::string name) {
        server_name_ = std::move(name);
    }

    // RFC 9622 Section 6.3.4. ALPN protocol identifiers, in order of preference.
    // Repeatable.
    void add_alpn(std::string protocol_id) {
        alpn_.push_back(std::move(protocol_id));
    }

    // RFC 9622 Section 6.3.5. When non-empty, restricts the TLS 1.3 cipher suites
    // / named groups to exactly this list (used to pin one of each for measurement).
    void set_ciphersuites(std::vector<std::string> suites) {
        ciphersuites_ = std::move(suites);
    }
    void set_supported_groups(std::vector<std::string> groups) {
        supported_groups_ = std::move(groups);
    }

    // RFC 9622 Section 6.3.2 (serverCertificate). Paths to the server's PEM
    // certificate chain and private key. Required on the listener side when TLS
    // is requested; unused on the client side.
    void set_certificate_chain_file(std::string path) {
        certificate_chain_file_ = std::move(path);
    }
    void set_private_key_file(std::string path) {
        private_key_file_ = std::move(path);
    }

    void set_pre_shared_key(std::string_view key) {
        pre_shared_keys_.emplace_back(key);
    }

    // Accessors for the security provider (which lives under src/).
    bool is_enabled() const noexcept { return !allowed_protocols_.empty(); }
    const std::vector<SecurityProtocol>& allowed_protocols() const noexcept { return allowed_protocols_; }
    TLSVersion min_tls_version() const noexcept { return min_tls_version_; }
    TLSVersion max_tls_version() const noexcept { return max_tls_version_; }
    const std::vector<std::string>& trust_anchors() const noexcept { return trust_ca_; }
    const std::string& server_name() const noexcept { return server_name_; }
    const std::vector<std::string>& alpn_protocols() const noexcept { return alpn_; }
    const std::vector<std::string>& ciphersuites() const noexcept { return ciphersuites_; }
    const std::vector<std::string>& supported_groups() const noexcept { return supported_groups_; }
    const std::string& certificate_chain_file() const noexcept { return certificate_chain_file_; }
    const std::string& private_key_file() const noexcept { return private_key_file_; }

private:
    std::vector<SecurityProtocol> allowed_protocols_;
    std::vector<std::string> pre_shared_keys_;
    std::vector<std::string> local_identity_;
    std::vector<std::string> trust_ca_;
    std::string server_name_;
    std::string certificate_chain_file_;
    std::string private_key_file_;
    std::vector<std::string> alpn_;
    std::vector<std::string> ciphersuites_;
    std::vector<std::string> supported_groups_;
    TLSVersion min_tls_version_ = TLSVersion::TLS_1_2;
    TLSVersion max_tls_version_ = TLSVersion::TLS_1_3;
};

// ============================================================================
// Endpoints
// ============================================================================

enum class AddressFamily {
    IPv4,
    IPv6,
    UNSPEC
};

class Endpoint {
public:
    explicit Endpoint(std::string hostname = {}, std::uint16_t port = 0, 
                     AddressFamily family = AddressFamily::UNSPEC)
        : hostname_(std::move(hostname)), port_(port), family_(family) {}
    
    const std::string& hostname() const noexcept { return hostname_; }
    std::uint16_t port() const noexcept { return port_; }
    AddressFamily family() const noexcept { return family_; }
    
    virtual asio::awaitable<std::vector<asio::ip::tcp::endpoint>> resolve(
        asio::io_context& ctx) const = 0;

    virtual ~Endpoint() = default;

protected:
    std::string hostname_;
    std::uint16_t port_;
    AddressFamily family_;
};

class LocalEndpoint : public Endpoint {
public:
    LocalEndpoint(): Endpoint() {}
    explicit LocalEndpoint(std::string hostname, std::uint16_t port)
        : Endpoint(std::move(hostname), port) {}
    
    LocalEndpoint with_hostname(std::string hostname) const {
        auto result = *this;
        result.hostname_ = std::move(hostname);
        return result;
    }
    
    LocalEndpoint with_port(std::uint16_t port) const {
        auto result = *this;
        result.port_ = port;
        return result;
    }
    
    asio::awaitable<std::vector<asio::ip::tcp::endpoint>> resolve(asio::io_context& ctx) const override;

};

class RemoteEndpoint : public Endpoint {
public:
    explicit RemoteEndpoint(std::string hostname, std::uint16_t port)
        : Endpoint(std::move(hostname), port) {}
    
    RemoteEndpoint with_hostname(std::string hostname) const {
        auto result = *this;
        result.hostname_ = std::move(hostname);
        return result;
    }
    
    RemoteEndpoint with_port(std::uint16_t port) const {
        auto result = *this;
        result.port_ = port;
        return result;
    }
    
    asio::awaitable<std::vector<asio::ip::tcp::endpoint>> resolve(
        asio::io_context& ctx) const override;

private:
    int priority_ = 0;
};

// ============================================================================
// Message System
// ============================================================================

enum class Priority {
    LOW = 0,
    NORMAL = 100,
    HIGH = 200,
    URGENT = 300
};

enum class Lifetime {
    SESSION,
    MESSAGE,
    RESPONSE
};

class MessageContext {
public:
    void set_priority(Priority priority) noexcept { priority_ = priority; }
    void set_lifetime(Lifetime lifetime) noexcept { lifetime_ = lifetime; }
    void set_ordered(bool ordered) noexcept { ordered_ = ordered; }
    void set_reliable(bool reliable) noexcept { reliable_ = reliable; }
    void set_timeout(std::chrono::milliseconds timeout) noexcept { timeout_ = timeout; }
    
    Priority priority() const noexcept { return priority_; }
    Lifetime lifetime() const noexcept { return lifetime_; }
    bool ordered() const noexcept { return ordered_; }
    bool reliable() const noexcept { return reliable_; }
    std::chrono::milliseconds timeout() const noexcept { return timeout_; }

private:
    Priority priority_ = Priority::NORMAL;
    Lifetime lifetime_ = Lifetime::SESSION;
    bool ordered_ = true;
    bool reliable_ = true;
    std::chrono::milliseconds timeout_{0};
};

class Message {
public:
    // Owning: Message takes ownership of the vector.
    explicit Message(std::vector<std::uint8_t> data, MessageContext context = {})
        : owned_data_(std::move(data)), owning_(true), context_(std::move(context)) {}

    // Non-owning: zero-copy send path (RFC 9623).
    // Caller must keep the referenced data alive for the duration of any send() call.
    explicit Message(std::span<const std::uint8_t> data, MessageContext context = {})
        : span_view_(data), owning_(false), context_(std::move(context)) {}

    // Chain-backed: the receive path delivers the payload as a sequence of pooled
    // blocks with no payload copy (modes C and D). `end_of_message` carries the
    // RFC 9623 endOfMessage flag: false for a ReceivedPartial fragment, true for
    // the final fragment or a whole Message.
    explicit Message(std::shared_ptr<const BlockChain> chain,
                     MessageContext context = {}, bool end_of_message = true)
        : chain_(std::move(chain)), owning_(false),
          end_of_message_(end_of_message), context_(std::move(context)) {}

    bool is_owning()  const noexcept { return owning_; }        // vector-backed
    bool is_chained() const noexcept { return chain_ != nullptr; }

    // RFC 9623 endOfMessage. Always true for the vector / span variants: a classic
    // complete Message is its own end.
    bool is_end_of_message() const noexcept { return end_of_message_; }

    // Total payload size in bytes, for any backing variant. O(1).
    std::size_t size() const noexcept;
    std::size_t length() const noexcept { return size(); }

    // The payload as one contiguous byte range. Cheap for the vector / span
    // variants; for the chain variant it gathers the blocks once into an internal
    // buffer and caches the result (not thread-safe). Use blocks() to consume a
    // chain-backed Message without this copy.
    std::span<const std::byte> as_bytes() const;

    // The payload as its constituent contiguous segments, in order (one segment
    // per pooled block; a single segment for the vector / span variants). Zero
    // copy. Each span is valid for the lifetime of this Message.
    std::vector<std::span<const std::byte>> blocks() const;

    // The block chain backing this Message, or nullptr for the vector / span
    // variants. Used by the transport send path for gather-write; BlockChain is
    // an implementation type, opaque to applications.
    const BlockChain* block_chain() const noexcept { return chain_.get(); }

    const MessageContext& context() const noexcept { return context_; }
    void set_context(MessageContext context) { context_ = std::move(context); }

private:
    // Gathers the chain into gathered_ on first call and returns a view of it.
    // Only meaningful when chain_ != nullptr.
    std::span<const std::byte> ensure_gathered() const;

    std::vector<std::uint8_t>          owned_data_;
    std::span<const std::uint8_t>      span_view_;
    std::shared_ptr<const BlockChain>  chain_;
    mutable std::shared_ptr<std::byte[]> gathered_;           // chain-variant cache
    mutable std::size_t               gathered_size_ = 0;
    mutable bool                      gathered_valid_ = false;
    bool                              owning_;
    bool                              end_of_message_ = true;
    MessageContext                    context_;
};

// ============================================================================
// Message Framing — see taps/message_framer.h (MessageFramer API v2, RFC 9623 §6)
// ============================================================================

// ============================================================================
// Connection States
// ============================================================================

enum class ConnectionState {
    ESTABLISHING,
    ESTABLISHED,
    CLOSING,
    CLOSED,
    ERROR
};

// ============================================================================
// Core TAPS Interfaces
// ============================================================================

class Connection {
public:
    virtual ~Connection() = default;
    
    virtual asio::awaitable<Result<void>> send(const Message& message) = 0;
    virtual asio::awaitable<Result<Message>> receive() = 0;
    virtual asio::awaitable<Result<void>> close() = 0;
    virtual asio::awaitable<Result<void>> abort() = 0;
    
    virtual RemoteEndpoint get_remote_endpoint() const = 0;
    virtual LocalEndpoint get_local_endpoint() const = 0;
    ConnectionState state() const noexcept{ return state_; }
    
    virtual void set_framer(std::unique_ptr<MessageFramer> framer){
        framer_ = std::move(framer);
    }

protected:
    ConnectionState state_ = ConnectionState::ESTABLISHING;
    std::unique_ptr<MessageFramer> framer_;
};

class Listener {
public:
    virtual ~Listener() = default;
    
    virtual asio::awaitable<Result<void>> listen() = 0;
    virtual asio::awaitable<Result<std::unique_ptr<Connection>>> accept() = 0;
    virtual asio::awaitable<Result<void>> stop() = 0;

protected:
    LocalEndpoint local_endpoint_;
    TransportProperties transport_properties_;
    SecurityParameters security_parameters_;
    bool is_listening_ = false;
};

class Preconnection {
public:
    // Out-of-line (defined in Preconnection.cpp): security_provider_ is a unique_ptr
    // to a forward-declared type, so the constructor's and destructor's cleanup code
    // must be emitted where SecurityProvider is complete.
    Preconnection(asio::io_context& ctx, LocalEndpoint local, RemoteEndpoint remote,
                  TransportProperties props, SecurityParameters security,
                  std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);
    ~Preconnection();

    asio::awaitable<Result<std::unique_ptr<Connection>>> initiate();

    void add_remote_endpoint(RemoteEndpoint endpoint) {
        remote_endpoints_.push_back(std::move(endpoint));
    }

    void set_transport_property(PropertyKey key, SelectionProperty value) {
        transport_properties_.set(key, value);
    }

private:
    asio::io_context& io_context_;
    LocalEndpoint local_endpoint_;
    //RemoteEndpoint remote_endpoint_;
    std::vector<RemoteEndpoint> remote_endpoints_;
    TransportProperties transport_properties_;
    SecurityParameters security_parameters_;
    std::shared_ptr<BlockPoolFactory> pool_factory_;
    // Built once, lazily, on the first establish_connection() that needs it.
    std::unique_ptr<SecurityProvider> security_provider_;

    asio::awaitable<Result<std::unique_ptr<Connection>>> initiate_with_single_endpoint();
    asio::awaitable<Result<std::unique_ptr<Connection>>> happy_eyeballs_racing();
    asio::awaitable<Result<std::unique_ptr<Connection>>> race_connections(const std::vector<asio::ip::tcp::endpoint>& endpoints);

    // Post-connect establishment: applies the security provider to a freshly
    // connected TCPConnection when SecurityParameters request it (handshake, peer
    // validation, ALPN), then hands it back as a Connection. Without security it
    // just forwards ownership. Both the single-endpoint path and the Happy Eyeballs
    // winner funnel through here. Takes the concrete type so no down-cast is needed.
    asio::awaitable<Result<std::unique_ptr<Connection>>> establish_connection(std::unique_ptr<TCPConnection> conn);
};

// A pluggable strategy for how each Connection obtains its receive-path
// BlockPool — the injection point ACE would call an allocator strategy.
// TransportServices owns one and threads it through every Preconnection /
// Listener / Connection it creates, so an app that needs e.g. a pre-warmed,
// bounded pool (no `new` once traffic starts — see HeapBlockPool's own
// lazy-growth caveat) supplies one factory, once, instead of reaching into
// every Connection subclass individually.
//
// make() is called once per Connection (or once per Listener, for the single
// shared pool behind UDPListener) — never on the per-message hot path — so a
// factory holding config (block size, pre-warm count, ...) and no other mutable
// state is safe to share (shared_ptr) across everything TransportServices
// spawns, without synchronization of its own.
class BlockPoolFactory {
public:
    virtual ~BlockPoolFactory() = default;
    virtual std::unique_ptr<BlockPool> make() const = 0;
};

// ============================================================================
// Transport Services Main Interface
// ============================================================================

class TransportServices {
public:
    // pool_factory: nullptr (the default) keeps today's behaviour — every
    // Connection gets its own HeapBlockPool. Supply one to override how ALL
    // Connections spawned from this TransportServices obtain their pool.
    explicit TransportServices(asio::io_context& ctx,
                               std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);

    Preconnection preconnect(LocalEndpoint local, RemoteEndpoint remote,
                           TransportProperties properties = {},
                           SecurityParameters security = {}) {
        return Preconnection(io_context_, std::move(local), std::move(remote),
                           std::move(properties), std::move(security), pool_factory_);
    }

    asio::awaitable<Result<std::unique_ptr<Listener>>> listen(
        LocalEndpoint local, TransportProperties properties = {},
        SecurityParameters security = {});

private:
    asio::io_context& io_context_;
    std::shared_ptr<BlockPoolFactory> pool_factory_;
};

// ============================================================================
// Concrete Implementations
// ============================================================================

class TCPConnection : public Connection {
public:
    explicit TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint,
                           std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);
    explicit TCPConnection(asio::ip::tcp::socket socket,
                           std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);
    ~TCPConnection();  // out-of-line: block_pool_ is a pimpl to a private type

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;
    
    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;

    asio::awaitable<Result<void>> connect();

    // Replace the plain I/O stream with a secured one produced by `provider`
    // (TLS handshake over the already-connected socket, peer validated against
    // `server_name`). Called by Preconnection during establishment; a no-op path
    // for the connection is never asked to do this when no security is requested.
    asio::awaitable<Result<void>> apply_security(SecurityProvider& provider,
                                                std::string server_name);

private:
    asio::ip::tcp::socket socket_;
    // Data-path I/O goes through here: a PlainStream over socket_ by default, swapped
    // for a TLS stream by the security provider at establishment. Declared after
    // socket_ so it is destroyed first (it holds a reference to socket_). connect(),
    // abort() and endpoint queries stay on socket_ directly.
    std::unique_ptr<ByteStream> stream_;
    asio::ip::tcp::endpoint remote_endpoint_;

    // Cached endpoints to avoid system calls
    std::optional<asio::ip::tcp::endpoint> cached_remote_endpoint_;
    std::optional<asio::ip::tcp::endpoint> cached_local_endpoint_;

    // Pool of fixed-size blocks for the receive path (framed and no-framer).
    std::unique_ptr<BlockPool> block_pool_;
    // Bytes received but not yet parsed by the framer, behind the receive cursor.
    std::unique_ptr<BlockChain> receive_chain_;
    bool receive_eof_ = false;
    // The block read_one_chunk() is currently filling; may be invalid (no block
    // checked out). Kept across calls so a small read doesn't strand the rest of
    // a block's capacity — see read_one_chunk().
    std::unique_ptr<BlockRef> current_block_;

    asio::awaitable<Result<Message>> receive_with_framing();
    asio::awaitable<Result<Message>> receive_without_framing();

    // Reads the next chunk of the byte-stream into a pooled block, reusing
    // current_block_'s leftover capacity across calls instead of checking out a
    // fresh block every time (a fresh block is preferred once the leftover space
    // drops below a quarter of the pool's block size, so a later read doesn't get
    // starved into an extra syscall). Each call's bytes are delivered as their own
    // refcounted window; several such windows may share one DataBlock. Returns an
    // empty/invalid BlockRef on a graceful close (receive_eof_ is set as a side
    // effect) — used identically by receive_with_framing() and
    // receive_without_framing(), so the block-reuse policy lives in one place.
    asio::awaitable<Result<BlockRef>> read_one_chunk();
};


class PassiveUDPConnection : public Connection {
public:

    explicit PassiveUDPConnection(asio::ip::udp::socket& socket, asio::ip::udp::endpoint endpoint, std::shared_ptr<Mailbox> mailbox);
    ~PassiveUDPConnection();

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;

    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;

    // Datagrams discarded (drop-oldest) because the receive ring was full while
    // the application was not consuming fast enough. UDP has no flow control.
    std::size_t datagrams_dropped() const noexcept;

    friend class UDPListener;

private:
    asio::ip::udp::socket & socket_; //referencia al socket del UDPListener
    asio::ip::udp::endpoint remote_endpoint_;
    asio::ip::udp::endpoint local_endpoint_;

    std::shared_ptr<Mailbox> mailbox_;
    std::function<void()> on_close_;
};

class ActiveUDPConnection : public Connection {
public:

    explicit ActiveUDPConnection(asio::io_context& ctx, asio::ip::udp::endpoint endpoint,
                                 std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);
    ~ActiveUDPConnection();  // out-of-line: block_pool_ points to a private type

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;

    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;

private:
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    // Fixed-size blocks for the receive path; one datagram per block, no copy.
    std::unique_ptr<BlockPool> block_pool_;
};

class TCPListener : public Listener {
public:
    explicit TCPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties = {},
                        SecurityParameters security = {},
                        std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);
    ~TCPListener();  // out-of-line: security_provider_ is a unique_ptr to a private type

    asio::awaitable<Result<void>> listen() override;
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept() override;
    asio::awaitable<Result<void>> stop() override;

    bool is_listening() const noexcept;

    LocalEndpoint get_local_endpoint() const;

private:
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    // Forwarded to each TCPConnection accept() spawns; see BlockPoolFactory.
    std::shared_ptr<BlockPoolFactory> pool_factory_;
    // Server-side TLS provider, built once (lazily) on the first accept() that
    // needs it when security_parameters_ request TLS.
    std::unique_ptr<SecurityProvider> security_provider_;
};

class UDPListener : public Listener {
public:
    explicit UDPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties = {},
                        SecurityParameters security = {},
                        std::shared_ptr<BlockPoolFactory> pool_factory = nullptr);
    ~UDPListener();  // out-of-line: block_pool_ points to a private type

    asio::awaitable<Result<void>> listen() override;
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept() override;
    asio::awaitable<Result<void>> stop() override;

private:
    // One live logical connection (one source endpoint) and its last-activity time.
    struct Conn {
        asio::ip::udp::endpoint             endpoint;
        std::shared_ptr<Mailbox>            mailbox;
        std::chrono::steady_clock::time_point last_active;
    };

    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;

    asio::strand<asio::io_context::executor_type> strand_;

    // LRU of live logical connections, most-recent-first; index_ maps a source
    // endpoint to its node. Both are touched only on strand_.
    std::list<Conn> lru_;
    std::unordered_map<asio::ip::udp::endpoint, std::list<Conn>::iterator> index_;

    asio::experimental::channel<void(std::error_code, std::unique_ptr<PassiveUDPConnection>)> accept_channel_;
    // One shared pool for the single receive loop; datagrams are one block each.
    std::unique_ptr<BlockPool> block_pool_;
    asio::steady_timer sweep_timer_;

    // Demux helpers, all run on strand_.
    std::shared_ptr<Mailbox> touch_or_create(const asio::ip::udp::endpoint& sender,
                                             bool& is_new);
    void evict(std::list<Conn>::iterator it);
    asio::awaitable<void> sweep_loop();
};

// ============================================================================
// Utility Functions
// ============================================================================

// Gather a Message's payload into the caller's contiguous buffer. `out` must be at
// least msg.size() bytes; returns the number of bytes written. Performs no
// allocation of its own (unlike Message::as_bytes(), which caches internally).
std::size_t gather(std::span<std::byte> out, const Message& msg);

// Non-owning factory for binary data — caller must keep the source alive through send().
template<std::ranges::contiguous_range R>
    requires std::same_as<std::ranges::range_value_t<R>, std::uint8_t>
Message make_message(R&& data, MessageContext context = {}) {
    return Message(std::span<const std::uint8_t>(std::ranges::data(data), std::ranges::size(data)),
                   std::move(context));
}

// Explicit non-owning aliases. The _view suffix signals that the caller owns the data.
inline Message make_message_view(std::span<const std::uint8_t> data, MessageContext context = {}) {
    return Message(data, std::move(context));
}

inline Message make_message_view(std::string_view text, MessageContext context = {}) {
    return Message(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()),
        std::move(context));
}

} // namespace taps