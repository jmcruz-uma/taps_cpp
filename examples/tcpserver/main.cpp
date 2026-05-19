#include "taps/taps_api.h"

#include <asio.hpp>
#include <format>
#include <print>

int main() {
    asio::io_context ctx;

    auto server_test = [&]() -> asio::awaitable<void> {
        taps::TransportServices ts(ctx);

        // Configurar propiedades para TCP
        taps::TransportProperties props;
        props.set(taps::PropertyKey::RELIABILITY, taps::SelectionProperty::REQUIRE);

        auto listen_result = co_await ts.listen(
            taps::LocalEndpoint{"127.0.0.1", 9999},  // Escuchar en 127.0.0.1:9999
            std::move(props)
        );

        if (!listen_result.has_value()) {
            std::println("Listen failed: {}", listen_result.error().message());
            co_return;
        }

        auto& listener = *listen_result;

        std::println("Server listening!");

        while (true) {
            auto accept_result = co_await listener->accept();
            if (!accept_result.has_value()) {
                std::println("Accept failed: {}", accept_result.error().message());
                continue;
            }

            auto conn = std::move(*accept_result);

            // Manejar la conexión en una coroutine separada
            co_spawn(ctx, [conn = std::move(conn)]() mutable -> asio::awaitable<void> {
                // Recibir mensaje del cliente
                auto receive_result = co_await conn->receive();
                if (!receive_result) {
                    std::println("Receive failed: {}", receive_result.error().message());
                    co_await conn->close();
                    co_return;
                }

                auto message = std::move(*receive_result);
                auto message_data = message.data();
                std::string received_msg(message_data.begin(), message_data.end());
                std::println("Message received: {}", received_msg);

                // Responder al cliente
                std::string response = "Mensaje recibido: " + received_msg;
                auto response_message = taps::make_message(response);
                auto send_result = co_await conn->send(std::move(response_message));

                if (!send_result) {
                    std::println("Send failed: {}", send_result.error().message());
                } else {
                    std::println("Response sent successfully!");
                }

                co_await conn->close();
            }, asio::detached);
        }
    };

    co_spawn(ctx, server_test(), asio::detached);
    ctx.run();
}