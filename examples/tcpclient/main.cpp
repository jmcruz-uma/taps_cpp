#include "taps/taps_api.h"

#include <asio.hpp>
#include <format>
#include <print>

int main(){

    asio::io_context ctx;

    auto client_test = [&]() -> asio::awaitable<void> {
        taps::TransportServices ts(ctx);
        
        // Configurar propiedades para TCP
        taps::TransportProperties props;
        props.set(taps::PropertyKey::RELIABILITY, taps::SelectionProperty::REQUIRE);
        
        auto preconn = ts.preconnect(
            taps::LocalEndpoint{},                    // Cualquier interfaz local
            taps::RemoteEndpoint{"localhost", 9999},  // Dirección del servidor
            std::move(props)
        );
        
        auto init_result = co_await preconn.initiate();
        if (!init_result.has_value()) {
            std::println("Connection failed: {}", init_result.error().message());
            co_return;
        }
        
        auto & conn = *init_result;
        // Enviar mensaje
        auto message = taps::make_message_view("Hola mundo (en TAPS)!\n");
        auto send_result = co_await conn->send(std::move(message));
        
        if (!send_result) {
            std::println("Send failed: {}", send_result.error().message());
            co_return;
        }
        
        std::println("Message sent successfully!");

        auto receive_result = co_await conn->receive();
        if (!receive_result) {
            std::print("TCP receive failed: {}\n", receive_result.error().message());
        }else{    
            auto message = std::move(*receive_result);
            auto message_data = message.as_bytes();
            std::string received_msg(reinterpret_cast<const char*>(message_data.data()), message_data.size());
            std::print("Message received: {}\n", received_msg);
        }

        co_await conn->close();
    };

    co_spawn(ctx, client_test(), asio::detached);
    ctx.run();

}