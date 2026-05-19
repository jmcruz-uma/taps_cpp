#include "taps/taps_api.h"

#include <asio.hpp>
#include <format>
#include <print>

int main(){

asio::io_context ctx;

auto udp_test = [&]() -> asio::awaitable<void> {
    taps::TransportServices ts(ctx);
    
    // Configurar propiedades para UDP (no reliable)
    taps::TransportProperties props;
    props.set(taps::PropertyKey::RELIABILITY, taps::SelectionProperty::AVOID);
    
    auto preconn = ts.preconnect(
        taps::LocalEndpoint{},
        taps::RemoteEndpoint{"localhost", 9999},
        std::move(props)
    );
    
    auto conn_result = co_await preconn.initiate();
    if (!conn_result) {
        std::println("UDP Connection failed: {}", conn_result.error().message());
        co_return;
    }
    
    auto& conn = *conn_result;
    
    // Enviar datagram
    auto message = taps::make_message_view("Hello UDP from TAPS!");
    auto send_result = co_await conn->send(std::move(message));
    
    if (send_result) {
        std::println("UDP message sent!");
    } else {
        std::println("UDP send failed: {}", send_result.error().message());
    }

    auto receive_result = co_await conn->receive();
    if (!receive_result) {
        std::print("UDP receive failed: {}\n", receive_result.error().message());
    }else{    
        auto message = std::move(*receive_result);
        auto message_data = message.data();
        std::string received_msg(message_data.begin(), message_data.end());
        std::print("Message received: {}\n", received_msg);
    }
    co_await conn->close();
};

co_spawn(ctx, udp_test(), asio::detached);
ctx.run();

}