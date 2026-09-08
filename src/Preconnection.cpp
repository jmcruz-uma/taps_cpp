#include "taps/taps_api.h"
#include "security/security_provider.h"
#ifdef TAPS_WITH_TLS
#include "security/tls_provider.h"
#endif
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <string>

namespace taps {

// Out-of-line: security_provider_ is a unique_ptr to a forward-declared type, so
// the constructor's and destructor's member cleanup is emitted here where
// SecurityProvider is complete.
Preconnection::Preconnection(asio::io_context& ctx, LocalEndpoint local, RemoteEndpoint remote,
                             TransportProperties props, SecurityParameters security,
                             std::shared_ptr<BlockPoolFactory> pool_factory)
    : io_context_(ctx), local_endpoint_(std::move(local)),
      transport_properties_(std::move(props)),
      security_parameters_(std::move(security)),
      pool_factory_(std::move(pool_factory)) {
    remote_endpoints_.push_back(std::move(remote));
}

Preconnection::~Preconnection() = default;

// ============================================================================
// Preconnection Implementation
// ============================================================================

asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::initiate() {
    // A single remote endpoint takes the direct path; two or more go through
    // Happy Eyeballs.
    if (remote_endpoints_.size() == 1) {
        co_return co_await initiate_with_single_endpoint();
    }

    co_return co_await happy_eyeballs_racing();
}


asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::initiate_with_single_endpoint() {
    auto asio_endpoints = co_await remote_endpoints_.at(0).resolve(io_context_);

    if (asio_endpoints.empty()) {
        co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED,
                                          "Failed to resolve remote endpoint"));
    }

    auto& endpoint = asio_endpoints[0];

    if (transport_properties_.requires_reliable_transport()) {
        // TCP
        try {
            auto tcp_conn = std::make_unique<TCPConnection>(io_context_, endpoint, pool_factory_);

            auto connect_result = co_await tcp_conn->connect();
            if (!connect_result) {
                co_await tcp_conn->abort();
                co_return std::unexpected(connect_result.error());
            }

            co_return co_await establish_connection(std::move(tcp_conn));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
        }
    } else {
        // UDP: convert the resolved TCP endpoint to a UDP one.
        asio::ip::udp::endpoint udp_endpoint(endpoint.address(), endpoint.port());

        try {
            auto udp_conn = std::make_unique<ActiveUDPConnection>(io_context_, udp_endpoint, pool_factory_);

            co_return std::unique_ptr<Connection>(std::move(udp_conn));
        } catch (const std::exception& e) {
            co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED, e.what()));
        }
    }
}


asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::happy_eyeballs_racing() {
    std::vector<asio::ip::tcp::endpoint> all_endpoints;

    try {
        // remote_endpoints_[0] is resolved first so its addresses lead the list
        // (RFC 8305 keeps the caller's preferred destination first); the rest
        // follow in order. Index 0 is skipped in the loop to avoid resolving it
        // twice.
        auto primary_resolved = co_await remote_endpoints_.at(0).resolve(io_context_);
        all_endpoints.insert(all_endpoints.end(), primary_resolved.begin(), primary_resolved.end());

        for (std::size_t i = 1; i < remote_endpoints_.size(); ++i) {
            auto resolved = co_await remote_endpoints_[i].resolve(io_context_);
            all_endpoints.insert(all_endpoints.end(), resolved.begin(), resolved.end());
        }

        if (all_endpoints.empty()) {
            co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED,
                                              "No addresses resolved"));
        }

    } catch (const std::exception& e) {
        co_return std::unexpected(TAPSError(ErrorType::RESOLUTION_FAILED, e.what()));
    }

    co_return co_await race_connections(all_endpoints);
}


/// Happy Eyeballs (RFC 8305) connection attempt over the resolved address list.
///
/// Staggered sequential attempts: the first address is tried immediately; each
/// further address is tried only after the previous attempt has failed, with a
/// 250 ms pause between attempts (RFC 8305 §5). The first address to connect
/// wins; every losing attempt is aborted before the next one starts.
///
/// Properties: no shared mutable state, no detached coroutines, no polling loop.
/// Correct and adequate for the common IPv4/IPv6 dual-stack case (1-3 addresses).
///
/// Limitation vs. a full RFC 8305 implementation: attempts do not overlap, so a
/// black-holed address is only abandoned once its own connect() times out rather
/// than after the 250 ms stagger. True parallel racing would need a timer raced
/// against each connect() (asio::experimental::parallel_group) with careful
/// Connection lifetime management across coroutines; deferred until a scenario
/// needs it.
asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::race_connections(
    const std::vector<asio::ip::tcp::endpoint>& endpoints) {

    using namespace std::chrono_literals;

    if (endpoints.empty()) {
        co_return std::unexpected(TAPSError(ErrorType::CONNECTION_FAILED,
                                          "No endpoints to connect to"));
    }

    TAPSError last_error{ErrorType::CONNECTION_FAILED, "No endpoints attempted"};

    for (std::size_t i = 0; i < endpoints.size(); ++i) {
        auto conn = std::make_unique<TCPConnection>(io_context_, endpoints[i], pool_factory_);

        auto connect_result = co_await conn->connect();
        if (connect_result) {
            co_return co_await establish_connection(std::move(conn));
        }

        // Failed: record the error, release this attempt, pause before the next.
        last_error = connect_result.error();
        co_await conn->abort();

        if (i + 1 < endpoints.size()) {
            asio::steady_timer stagger(io_context_, 250ms);
            co_await stagger.async_wait(asio::use_awaitable);
        }
    }

    co_return std::unexpected(TAPSError(ErrorType::CONNECTION_TIMEOUT,
                                      "All " + std::to_string(endpoints.size()) +
                                      " connection attempts failed: " + last_error.message()));
}


asio::awaitable<Result<std::unique_ptr<Connection>>> Preconnection::establish_connection(
    std::unique_ptr<TCPConnection> conn) {

    if (!security_parameters_.is_enabled()) {
        co_return std::unique_ptr<Connection>(std::move(conn));
    }

#ifdef TAPS_WITH_TLS
    if (!security_provider_) {
        auto provider = TlsProvider::create(security_parameters_, TlsProvider::Role::Client);
        if (!provider) {
            co_await conn->abort();
            co_return std::unexpected(provider.error());
        }
        security_provider_ = std::move(*provider);
    }

    // Identity to validate the peer against: the explicit server name if set,
    // otherwise the remote endpoint's hostname.
    std::string server_name = security_parameters_.server_name().empty()
        ? remote_endpoints_.at(0).hostname()
        : security_parameters_.server_name();

    auto secured = co_await conn->apply_security(*security_provider_, std::move(server_name));
    if (!secured) {
        co_await conn->abort();
        co_return std::unexpected(secured.error());
    }
    co_return std::unique_ptr<Connection>(std::move(conn));
#else
    co_await conn->abort();
    co_return std::unexpected(TAPSError{
        ErrorType::INVALID_CONFIGURATION,
        "SecurityParameters request TLS but this build has TAPS_WITH_TLS=OFF"});
#endif
}

} // namespace taps
