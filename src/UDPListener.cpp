#include "taps/taps_api.h"
#include "taps/mailbox.h"
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>
#include <unordered_map>
#include <memory>

namespace taps {

// ============================================================================
// UDPListener

// Invariant: UDPListener outlives all PassiveUDPConnection instances.
// on_close callbacks may safely capture `this`.
// ============================================================================

UDPListener::UDPListener(
    asio::io_context& ctx,
    LocalEndpoint local,
    TransportProperties properties,
    SecurityParameters security)
: io_context_(ctx)
, socket_(ctx)
, strand_(asio::make_strand(ctx))
, accept_channel_(io_context_.get_executor(), 100)
{
    local_endpoint_       = std::move(local);
    transport_properties_ = std::move(properties);
    security_parameters_  = std::move(security);
}

asio::awaitable<Result<void>> UDPListener::listen() {
    try {
        auto endpoints = co_await local_endpoint_.resolve(io_context_);
        if (endpoints.empty()) {
            co_return std::unexpected(
                TAPSError(ErrorType::RESOLUTION_FAILED,
                         "Failed to resolve local endpoint"));
        }

        asio::ip::udp::endpoint udp_ep(
            endpoints[0].address(),
            endpoints[0].port());

        socket_.open(udp_ep.protocol());
        socket_.set_option(asio::ip::udp::socket::reuse_address(true));
        socket_.bind(udp_ep);

        is_listening_ = true;

        asio::co_spawn(
            socket_.get_executor(),
            [this]() -> asio::awaitable<void> {
                std::vector<uint8_t> buffer(65536);
                asio::ip::udp::endpoint sender;

                while (true) {
                    std::size_t n =
                        co_await socket_.async_receive_from(
                            asio::buffer(buffer),
                            sender,
                            asio::use_awaitable);

                    std::vector<uint8_t> data(buffer.begin(),
                                              buffer.begin() + n);

                    asio::co_spawn(
                        strand_,
                        [this, sender, data = std::move(data)]() mutable   
                            -> asio::awaitable<void> {

                            auto it = mailboxes_.find(sender);
                            if (it == mailboxes_.end()) {
                                // New "logical connection"
                                auto mailbox =
                                    std::make_shared<Mailbox>(
                                        strand_);

                                auto conn =
                                    std::make_unique<PassiveUDPConnection>(
                                        socket_, sender, mailbox);

                                mailboxes_[sender] = mailbox;

                                conn->on_close_ = [this, sender] {
                                    asio::post(strand_, [this, sender] {
                                        mailboxes_.erase(sender);
                                    });
                                };

                                co_await accept_channel_.async_send(
                                    std::error_code{},
                                    std::move(conn),
                                    asio::as_tuple(asio::use_awaitable));

                                mailbox->deliver(std::move(data));
                            } else {
                              /*  if (auto mailbox = it->second.lock()) {
                                    mailbox->deliver(std::move(data));
                                } else {
                                    // dead mailbox, remove it
                                    mailboxes_.erase(it);
                                    println("Warning: Dropping packet from {}:{} due to expired mailbox",
                                            sender.address().to_string(),
                                            sender.port());
                                }
                                */
                                it->second->deliver(std::move(data));
                            }
                        },
                        asio::detached);
                }
            },
            asio::detached);

        co_return Result<void>{std::in_place};

    } catch (const std::exception& e) {
        co_return std::unexpected(
            TAPSError(ErrorType::INTERNAL_ERROR, e.what()));
    }
}

asio::awaitable<Result<std::unique_ptr<Connection>>> UDPListener::accept() {
    if (!is_listening_) {
        co_return std::unexpected(
            TAPSError(ErrorType::INVALID_CONFIGURATION,
                     "Not listening"));
    }

    auto [ec, conn] =
        co_await accept_channel_.async_receive(
            asio::as_tuple(asio::use_awaitable));

    if (ec) {
        co_return std::unexpected(
            TAPSError(ErrorType::INTERNAL_ERROR, ec.message()));
    }
    conn->state_ = ConnectionState::ESTABLISHED;
    co_return Result<std::unique_ptr<Connection>>(std::move(conn));
}

asio::awaitable<Result<void>> UDPListener::stop() {
    socket_.close();
    is_listening_ = false;
    mailboxes_.clear();
    co_return Result<void>{std::in_place};
}

} // namespace taps