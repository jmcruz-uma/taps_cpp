#include "taps/taps_api.h"
#include <asio.hpp>
#include <print>

int main() {
    asio::io_context ctx;
    
    auto udp_server = [&]() -> asio::awaitable<void> {
        taps::TransportServices ts(ctx);
        
        // Configurar propiedades para UDP (no reliable)
        taps::TransportProperties props;
        props.set(taps::PropertyKey::RELIABILITY, taps::SelectionProperty::AVOID);
        
        // Crear listener en lugar de preconnect
        auto listener_result = co_await ts.listen(
            taps::LocalEndpoint{"0.0.0.0", 9999},
            std::move(props)
        );
        
        if (!listener_result) {
            std::print("UDP Listener creation failed: {}\n", listener_result.error().message());
            co_return;
        }
        
        auto listener = std::move(*listener_result);
        co_await listener->listen();
        std::print("UDP Server listening on port 9999...\n");
        
        while (true) {
            // Esperar conexión entrante
            auto conn_result = co_await listener->accept();
            if (!conn_result) {
                std::print("UDP Connection accept failed: {}\n", conn_result.error().message());
                continue;
            }
            
            auto conn = std::move(*conn_result);
            std::print("UDP Connection established!\n");
            
            // Handle only one message exchange per connection (to prevent blocking)
            auto receive_result = co_await conn->receive();
            if (!receive_result) {
                std::print("UDP receive failed: {}\n", receive_result.error().message());
                co_await conn->close();
                continue;
            }
            
            auto message = std::move(*receive_result);
            auto message_data = message.data();
            std::string received_msg(message_data.begin(), message_data.end());
            std::print("Message received: {}\n", received_msg);
            
            // Enviar respuesta
            auto response = taps::make_message("Server received: " + received_msg);
            auto send_result = co_await conn->send(std::move(response));
            if (send_result) {
                std::print("UDP response sent!\n");
            } else {
                std::print("UDP send failed: {}\n", send_result.error().message());
            }
            
            co_await conn->close();
        }
    };
    
    co_spawn(ctx, udp_server(), asio::detached);
    ctx.run();
}