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
#include <iterator>
#include <memory_resource>
#include <functional>
#include <chrono>
#include <cstddef>
#include <span>
#include <expected>
#include <optional>
#include <unordered_map>
#include <bit>

namespace taps {

// Forward declarations
class Message;
class MessageContext;
class MessageFramer;
class BlockChain;        // src/buffer/block_chain.h — receive-path substrate (private)
class BlockRef;          // src/buffer/block.h       — receive-path substrate (private)
class MessageBlockPool;  // src/buffer/message_block_pool.h (private)
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
class UDPDemux;

// ============================================================================
// Error Handling
// ============================================================================

// An error is reported as an RFC 9622 event plus a reason. The event says what
// failed and whether the Connection survives: SEND_ERROR and RECEIVE_ERROR leave
// it usable; CONNECTION_ERROR means it has ended (state CLOSED).
enum class ErrorEvent {
    ESTABLISHMENT_ERROR,   // RFC 9622 Sections 7.1 and 7.2 (Connection or Listener)
    SEND_ERROR,            // RFC 9622 Section 9.2.2.3
    RECEIVE_ERROR,         // RFC 9622 Section 9.3.2.3
    CONNECTION_ERROR       // RFC 9622 Section 10
};

// Reasons from RFC 9623 Appendix B, followed by those this implementation adds
// where the Appendix has no name.
enum class ErrorReason {
    INVALID_CONFIGURATION,  // Properties or Endpoints contradictory or incomplete
    NO_CANDIDATES,          // valid configuration, no available protocol satisfies it
    RESOLUTION_FAILED,      // an Endpoint could not be resolved
    ESTABLISHMENT_FAILED,   // no transport-layer connection to the Remote Endpoint
    POLICY_PROHIBITED,      // the system forbids the action
    MESSAGE_TOO_LARGE,      // the Message is too big to handle
    PROTOCOL_FAILED,        // the underlying Protocol Stack failed
    DEFRAMING_FAILED,       // received data could not be processed by the Message Framer
    CONNECTION_ABORTED,     // the peer aborted the connection
    TIMEOUT,                // delivery was not possible after a timeout

    LOCAL_ABORT,                 // the application called abort() (RFC 9622 Section 10)
    LOCAL_ENDPOINT_UNAVAILABLE,  // the Local Endpoint is in use on this system
    INVALID_STATE,               // the operation is not valid in the current state
    RESOURCE_EXHAUSTED,          // memory or descriptors for the operation ran out
    IDLE_TIMEOUT,                // the Connection was ended after staying idle
    INTERNAL_ERROR               // unexpected failure inside the implementation
};

class TAPSError {
public:
    TAPSError(ErrorEvent event, ErrorReason reason, std::string message)
        : event_(event), reason_(reason), message_(std::move(message)) {}

    ErrorEvent event() const noexcept { return event_; }
    ErrorReason reason() const noexcept { return reason_; }
    const std::string& message() const noexcept { return message_; }

private:
    ErrorEvent event_;
    ErrorReason reason_;
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

// Diagnostic view of the parameters a secured Connection actually negotiated.
// Connection::security_info() returns one of these once the TLS handshake has
// completed, and std::nullopt otherwise (a plain Connection, or one not yet
// established). It is for logging and for test / benchmark harnesses that must
// confirm every peer negotiated identical cryptographic parameters; it is not a
// control surface and nothing on the data path reads it. Every field is the
// value as OpenSSL reports it, or "" when it does not apply.
struct SecurityInfo {
    std::string openssl_version;  // OpenSSL_version(OPENSSL_VERSION) as linked into the library
    std::string tls_version;      // e.g. "TLSv1.3"
    std::string cipher;           // e.g. "TLS_AES_128_GCM_SHA256"
    std::string group;            // key-exchange group, e.g. "X25519"
    std::string alpn;             // negotiated ALPN protocol id, "" if none
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
    // copy and no allocation: a forward range of std::span<const std::byte>. The
    // range and each span are valid for the lifetime of this Message.
    class Segments;
    Segments blocks() const noexcept;

    // The block chain backing this Message, or nullptr for the vector / span
    // variants. Used by the transport send path for gather-write; BlockChain is
    // an implementation type, opaque to applications.
    const BlockChain* block_chain() const noexcept { return chain_.get(); }

    const MessageContext& context() const noexcept { return context_; }
    void set_context(MessageContext context) { context_ = std::move(context); }

private:
    friend class Segments;
    std::size_t segment_count() const noexcept;
    std::span<const std::byte> segment(std::size_t i) const noexcept;

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

// The range Message::blocks() returns.
class Message::Segments {
public:
    class iterator {
    public:
        using value_type        = std::span<const std::byte>;
        using difference_type   = std::ptrdiff_t;
        using iterator_concept  = std::forward_iterator_tag;
        using iterator_category = std::forward_iterator_tag;

        iterator() noexcept = default;
        value_type operator*() const noexcept { return msg_->segment(i_); }
        iterator& operator++() noexcept { ++i_; return *this; }
        iterator operator++(int) noexcept { iterator old = *this; ++i_; return old; }
        bool operator==(const iterator&) const noexcept = default;

    private:
        friend class Segments;
        iterator(const Message* msg, std::size_t i) noexcept : msg_(msg), i_(i) {}
        const Message* msg_ = nullptr;
        std::size_t    i_ = 0;
    };

    iterator    begin() const noexcept { return {msg_, 0}; }
    iterator    end()   const noexcept { return {msg_, count_}; }
    std::size_t size()  const noexcept { return count_; }
    bool        empty() const noexcept { return count_ == 0; }

private:
    friend class Message;
    Segments(const Message* msg, std::size_t count) noexcept : msg_(msg), count_(count) {}
    const Message* msg_;
    std::size_t    count_;
};

inline Message::Segments Message::blocks() const noexcept {
    return Segments(this, segment_count());
}

// ============================================================================
// Message Framing — see taps/message_framer.h (MessageFramer API v2, RFC 9623 §6)
// ============================================================================

// ============================================================================
// Connection States
// ============================================================================

// RFC 9622 Section 11. A Connection that ends because of an error goes to CLOSED;
// the error itself is reported by the CONNECTION_ERROR (or ESTABLISHMENT_ERROR)
// returned by the operation that observed it.
enum class ConnectionState {
    ESTABLISHING,
    ESTABLISHED,
    CLOSING,
    CLOSED
};

// ============================================================================
// Core TAPS Interfaces
// ============================================================================

class Connection {
public:
    virtual ~Connection() = default;
    
    virtual asio::awaitable<Result<void>> send(const Message& message) = 0;
    virtual asio::awaitable<Result<Message>> receive() = 0;

    // Graceful termination (RFC 9622 Section 10; for TCP, RFC 9623 Section 10.1):
    // ends this side and completes, in state CLOSED, once the peer has ended its
    // side. What the peer still sends meanwhile is discarded, and a pending
    // receive() completes with RECEIVE_ERROR / INVALID_STATE. Must not be called
    // while a send() is pending. A peer that never ends keeps close() waiting;
    // abort() ends it.
    virtual asio::awaitable<Result<void>> close() = 0;
    // Immediate termination: pending operations complete with CONNECTION_ERROR /
    // LOCAL_ABORT.
    virtual asio::awaitable<Result<void>> abort() = 0;
    
    virtual RemoteEndpoint get_remote_endpoint() const = 0;
    virtual LocalEndpoint get_local_endpoint() const = 0;
    ConnectionState state() const noexcept{ return state_; }

    // RFC 9622 Sections 8.1.11.2 and 8.1.11.3 (canSend, canReceive). After the
    // peer has ended its side of a TCP connection the Connection stays ESTABLISHED
    // and can still send, but no longer receive (RFC 9623 Section 10.1).
    virtual bool can_send() const noexcept { return state_ == ConnectionState::ESTABLISHED; }
    virtual bool can_receive() const noexcept { return state_ == ConnectionState::ESTABLISHED; }

    virtual void set_framer(std::unique_ptr<MessageFramer> framer){
        framer_ = std::move(framer);
    }

    // The TLS parameters this Connection negotiated, or std::nullopt if it is not
    // secured. Non-const: reading them goes through asio::ssl::stream, whose
    // native_handle() has no const overload. Diagnostic only (see SecurityInfo).
    virtual std::optional<SecurityInfo> security_info() { return std::nullopt; }

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

// ============================================================================
// Message memory
// ============================================================================
//
// RFC 9622/9623 leave the ownership and storage of Message data to the
// implementation. In taps_cpp, all memory that holds or describes message data
// (received blocks, block lists, the contiguous buffer as_bytes() builds) comes
// from one std::pmr::memory_resource, chosen here. Nothing else uses it.
//
// The resource must outlive every Connection, Listener and Message that uses it.
//
// THE DEFAULT RESOURCE IS NOT THREAD-SAFE. It is a process-wide
// std::pmr::unsynchronized_pool_resource with message_pool_options(), which
// recycles the receive blocks. If the io_context runs on several threads and more
// than one coroutine receives or holds received Messages, pass a thread-safe
// resource, for example a std::pmr::synchronized_pool_resource built with
// message_pool_options().
struct MessageMemoryConfig {
    std::pmr::memory_resource* resource = nullptr;  // nullptr: default_message_resource()
    std::size_t block_size = 64 * 1024;             // bytes per receive block
    std::size_t max_live_blocks = 0;                // per Connection (or UDP Listener);
                                                    // 0 = no cap. At the cap, receive()
                                                    // fails with RESOURCE_EXHAUSTED.
};

// Pool options for message memory: blocks up to 64 KiB (the default block size)
// are pooled, in chunks of at most 16 blocks.
std::pmr::pool_options message_pool_options() noexcept;

// The process-wide default resource (not thread-safe; see MessageMemoryConfig).
std::pmr::memory_resource* default_message_resource();

class Preconnection {
public:
    // Out-of-line (defined in Preconnection.cpp): security_provider_ is a unique_ptr
    // to a forward-declared type, so the constructor's and destructor's cleanup code
    // must be emitted where SecurityProvider is complete.
    Preconnection(asio::io_context& ctx, LocalEndpoint local, RemoteEndpoint remote,
                  TransportProperties props, SecurityParameters security,
                  MessageMemoryConfig memory = {});
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
    MessageMemoryConfig memory_;
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

// ============================================================================
// Transport Services Main Interface
// ============================================================================

class TransportServices {
public:
    // `memory` applies to every Connection and Listener created from here.
    explicit TransportServices(asio::io_context& ctx, MessageMemoryConfig memory = {});

    Preconnection preconnect(LocalEndpoint local, RemoteEndpoint remote,
                           TransportProperties properties = {},
                           SecurityParameters security = {}) {
        return Preconnection(io_context_, std::move(local), std::move(remote),
                           std::move(properties), std::move(security), memory_);
    }

    asio::awaitable<Result<std::unique_ptr<Listener>>> listen(
        LocalEndpoint local, TransportProperties properties = {},
        SecurityParameters security = {});

private:
    asio::io_context& io_context_;
    MessageMemoryConfig memory_;
};

// ============================================================================
// Concrete Implementations
// ============================================================================

class TCPConnection : public Connection {
public:
    explicit TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint,
                           const MessageMemoryConfig& memory = {});
    explicit TCPConnection(asio::ip::tcp::socket socket,
                           const MessageMemoryConfig& memory = {});
    ~TCPConnection();  // out-of-line: block_pool_ is a pimpl to a private type

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;
    
    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;
    std::optional<SecurityInfo> security_info() override;
    bool can_receive() const noexcept override;

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
    std::unique_ptr<MessageBlockPool> block_pool_;
    // Bytes received but not yet parsed by the framer, behind the receive cursor.
    std::unique_ptr<BlockChain> receive_chain_;
    bool receive_eof_ = false;
    // The end of the peer's stream (or the error that ended it) has been delivered:
    // receive() has nothing more to return.
    bool receive_ended_ = false;
    // The last Message delivered had endOfMessage = false: a later end of stream
    // leaves that Message incomplete.
    bool message_open_ = false;
    // abort() was called: cancelled operations report LOCAL_ABORT.
    bool aborted_ = false;
    // The block read_one_chunk() is currently filling; may be invalid (no block
    // checked out). Kept across calls so a small read doesn't strand the rest of
    // a block's capacity — see read_one_chunk().
    std::unique_ptr<BlockRef> current_block_;

    asio::awaitable<Result<Message>> receive_with_framing();
    asio::awaitable<Result<Message>> receive_without_framing();

    // Classifies a receive-path failure and applies its effect on state_.
    TAPSError receive_failure(TAPSError error);

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

    // Created by the UDP Listener's demultiplexer for each new source.
    PassiveUDPConnection(std::shared_ptr<UDPDemux> demux, asio::ip::udp::endpoint remote,
                         std::shared_ptr<Mailbox> mailbox);
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

    friend class UDPDemux;

private:
    // Removes this Connection's source from the demultiplexer, once.
    void release() noexcept;

    std::shared_ptr<UDPDemux> demux_;   // shared with the Listener and its other Connections
    asio::ip::udp::endpoint remote_endpoint_;
    std::shared_ptr<Mailbox> mailbox_;
    bool aborted_ = false;
    bool released_ = false;
};

class ActiveUDPConnection : public Connection {
public:

    explicit ActiveUDPConnection(asio::io_context& ctx, asio::ip::udp::endpoint endpoint,
                                 const MessageMemoryConfig& memory = {});
    ~ActiveUDPConnection();  // out-of-line: block_pool_ points to a private type

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;

    // The socket is opened by the first send(): sending is possible before then.
    bool can_send() const noexcept override { return state_ != ConnectionState::CLOSED; }

    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;

private:
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    // Fixed-size blocks for the receive path; one datagram per block, no copy.
    std::unique_ptr<MessageBlockPool> block_pool_;
    bool aborted_ = false;
};

class TCPListener : public Listener {
public:
    explicit TCPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties = {},
                        SecurityParameters security = {},
                        MessageMemoryConfig memory = {});
    ~TCPListener();  // out-of-line: security_provider_ is a unique_ptr to a private type

    asio::awaitable<Result<void>> listen() override;
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept() override;
    asio::awaitable<Result<void>> stop() override;

    bool is_listening() const noexcept;

    LocalEndpoint get_local_endpoint() const;

private:
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    // Given to each TCPConnection accept() creates.
    MessageMemoryConfig memory_;
    // Server-side TLS provider, built once (lazily) on the first accept() that
    // needs it when security_parameters_ request TLS.
    std::unique_ptr<SecurityProvider> security_provider_;
};

class UDPListener : public Listener {
public:
    explicit UDPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties = {},
                        SecurityParameters security = {},
                        MessageMemoryConfig memory = {});
    // Stops accepting; Connections already accepted keep working (they share the
    // socket, which closes when the last of them goes).
    ~UDPListener();

    asio::awaitable<Result<void>> listen() override;
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept() override;
    asio::awaitable<Result<void>> stop() override;

private:
    asio::io_context& io_context_;
    std::shared_ptr<UDPDemux> demux_;   // socket, demultiplexing table, receive loop
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