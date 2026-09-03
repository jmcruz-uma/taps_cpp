#pragma once

#include <asio/awaitable.hpp>
#include <asio/strand.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/experimental/channel.hpp>

#include "taps/message_framer.h"   // taps::MessageFramer (API v2), ReceiveCursor, ParseResult

#include <string>
#include <vector>
#include <map>
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
class Connection;
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

class SecurityParameters {
public:
    void set_tls_version_range(TLSVersion min_version, TLSVersion max_version) {
        min_tls_version_ = min_version;
        max_tls_version_ = max_version;
    }
    
    void set_pre_shared_key(std::string_view key) {
        pre_shared_keys_.emplace_back(key);
    }

private:
    std::vector<std::string> pre_shared_keys_;
    std::vector<std::string> local_identity_;
    std::vector<std::string> trust_ca_;
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
    // Owning: Message takes ownership of the vector. (Legacy receive path.)
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

    // Total payload size in bytes, for any backing variant.
    std::size_t size() const noexcept;

    // Contiguous view of the payload. Cheap for the vector / span variants; for the
    // chain variant it materialises the bytes once into an internal buffer and
    // caches them (not thread-safe).
    std::span<const std::byte> linearize();

    // Valid only for the span variant (non-owning send path).
    std::span<const std::uint8_t> view() const noexcept { return span_view_; }

    // Contiguous byte view regardless of variant. Cheap for vector / span; forces
    // linearize() for the chain variant.
    std::span<const std::uint8_t> as_span() const;

    // Legacy contiguous accessor. Prefer linearize() / size(). For the chain
    // variant this linearises into an internal vector and returns a reference to it.
    const std::vector<std::uint8_t>& data() const;

    const MessageContext& context() const noexcept { return context_; }
    void set_context(MessageContext context) { context_ = std::move(context); }
    std::size_t length() const noexcept { return size(); }

private:
    // Fills and returns the chain-variant linearisation cache. Only meaningful when
    // chain_ != nullptr.
    const std::vector<std::uint8_t>& ensure_linearized() const;

    std::vector<std::uint8_t>         owned_data_;
    std::span<const std::uint8_t>     span_view_;
    std::shared_ptr<const BlockChain> chain_;
    mutable std::vector<std::uint8_t> linearized_;            // chain-variant cache
    mutable bool                      linearized_valid_ = false;
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

    Result<Message> make_message(std::vector<uint8_t>&& buffer);

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
    Preconnection(asio::io_context& ctx, LocalEndpoint local, RemoteEndpoint remote,
                 TransportProperties props, SecurityParameters security)
        : io_context_(ctx), local_endpoint_(std::move(local)), 
          transport_properties_(std::move(props)),
          security_parameters_(std::move(security)) { 
            remote_endpoints_.push_back(std::move(remote)); }
    
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
    
    asio::awaitable<Result<std::unique_ptr<Connection>>> initiate_with_single_endpoint();
    asio::awaitable<Result<std::unique_ptr<Connection>>> happy_eyeballs_racing();
    asio::awaitable<Result<std::unique_ptr<Connection>>> race_connections(const std::vector<asio::ip::tcp::endpoint>& endpoints);
};

// ============================================================================
// Transport Services Main Interface
// ============================================================================

class TransportServices {
public:
    explicit TransportServices(asio::io_context& ctx) : io_context_(ctx) {}
    
    Preconnection preconnect(LocalEndpoint local, RemoteEndpoint remote,
                           TransportProperties properties = {},
                           SecurityParameters security = {}) {
        return Preconnection(io_context_, std::move(local), std::move(remote),
                           std::move(properties), std::move(security));
    }
    
    asio::awaitable<Result<std::unique_ptr<Listener>>> listen(
        LocalEndpoint local, TransportProperties properties = {},
        SecurityParameters security = {});

private:
    asio::io_context& io_context_;
};

// ============================================================================
// Concrete Implementations
// ============================================================================

class TCPConnection : public Connection {
public:
    explicit TCPConnection(asio::io_context& ctx, asio::ip::tcp::endpoint endpoint);
    explicit TCPConnection(asio::ip::tcp::socket socket);
    ~TCPConnection();  // out-of-line: block_pool_ is a pimpl to a private type

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;
    
    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;

    asio::awaitable<Result<void>> connect();

private:
    asio::ip::tcp::socket socket_;
    asio::ip::tcp::endpoint remote_endpoint_;

    // Cached endpoints to avoid system calls
    std::optional<asio::ip::tcp::endpoint> cached_remote_endpoint_;
    std::optional<asio::ip::tcp::endpoint> cached_local_endpoint_;

    // Pool of fixed-size blocks for the receive path (framed and no-framer).
    std::unique_ptr<BlockPool> block_pool_;
    // Bytes received but not yet parsed by the framer, behind the receive cursor.
    std::unique_ptr<BlockChain> receive_chain_;
    bool receive_eof_ = false;

    asio::awaitable<Result<Message>> receive_with_framing();
    asio::awaitable<Result<Message>> receive_without_framing();
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

    explicit ActiveUDPConnection(asio::io_context& ctx, asio::ip::udp::endpoint endpoint);

    asio::awaitable<Result<void>> send(const Message& message) override;
    asio::awaitable<Result<Message>> receive() override;
    asio::awaitable<Result<void>> close() override;
    asio::awaitable<Result<void>> abort() override;
    
    RemoteEndpoint get_remote_endpoint() const override;
    LocalEndpoint get_local_endpoint() const override;
    
private:
    asio::ip::udp::socket socket_; 
    asio::ip::udp::endpoint remote_endpoint_;
};

class TCPListener : public Listener {
public:
    explicit TCPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties = {},
                        SecurityParameters security = {});
    
    asio::awaitable<Result<void>> listen() override;
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept() override;
    asio::awaitable<Result<void>> stop() override;

    bool is_listening() const noexcept;
    
    LocalEndpoint get_local_endpoint() const;

private:
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
};

class UDPListener : public Listener {
public:
    explicit UDPListener(asio::io_context& ctx, LocalEndpoint local,
                        TransportProperties properties = {},
                        SecurityParameters security = {});
    
    asio::awaitable<Result<void>> listen() override;
    asio::awaitable<Result<std::unique_ptr<Connection>>> accept() override;
    asio::awaitable<Result<void>> stop() override;

private:
    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;

    asio::strand<asio::io_context::executor_type> strand_;
    std::unordered_map<asio::ip::udp::endpoint, std::shared_ptr<Mailbox>> mailboxes_;
    asio::experimental::channel<void(std::error_code, std::unique_ptr<PassiveUDPConnection>)> accept_channel_;
};

// ============================================================================
// Utility Functions
// ============================================================================

template<typename T>
concept MessageLike = requires(T t) {
    { t.data() } -> std::convertible_to<std::span<const std::uint8_t>>;
};

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