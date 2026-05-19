#pragma once

#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>


namespace taps {

// ==============================
// Mailbox (internal use only)
// ==============================

class Mailbox {
public:
    using channel_type =
        asio::experimental::channel<void(std::error_code, std::vector<uint8_t>)>;

    explicit Mailbox(asio::any_io_executor exec, std::size_t capacity = 16)
        : channel_(exec, capacity)
    {}

    void deliver(std::vector<uint8_t> data) {
        channel_.async_send(
            std::error_code{},
            std::move(data),
            asio::detached
        );
    }

    asio::awaitable<std::vector<uint8_t>> receive() {
        auto [ec, data] =
            co_await channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec)
            throw std::system_error(ec);
        co_return std::move(data);
    }

    void close() {
        channel_.close();
    }

private:
    channel_type channel_;
};

} // namespace taps