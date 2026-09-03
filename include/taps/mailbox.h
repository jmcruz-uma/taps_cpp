#pragma once

#include <asio/any_io_executor.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>

#include <cstddef>
#include <memory>
#include <system_error>

namespace taps {

class BlockChain;  // src/buffer/block_chain.h (private) — one datagram per chain

// ==============================
// Mailbox (internal use only)
// ==============================
//
// Per-logical-UDP-connection queue of received datagrams. Each datagram is a
// single-block BlockChain drawn from the UDPListener's BlockPool; nothing here
// copies the payload.
class Mailbox {
public:
    using value_type   = std::shared_ptr<BlockChain>;
    using channel_type = asio::experimental::channel<void(std::error_code, value_type)>;

    explicit Mailbox(asio::any_io_executor exec, std::size_t capacity = 16)
        : channel_(exec, capacity)
    {}

    void deliver(value_type datagram) {
        channel_.async_send(std::error_code{}, std::move(datagram), asio::detached);
    }

    asio::awaitable<value_type> receive() {
        auto [ec, datagram] =
            co_await channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec)
            throw std::system_error(ec);
        co_return std::move(datagram);
    }

    void close() {
        channel_.close();
    }

private:
    channel_type channel_;
};

} // namespace taps
