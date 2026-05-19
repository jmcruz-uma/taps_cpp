#include "taps/taps_api.h"
#include <asio/use_awaitable.hpp>

namespace taps{

// ============================================================================
// Endpoint Implementations
// ============================================================================

asio::awaitable<std::vector<asio::ip::tcp::endpoint>> LocalEndpoint::resolve(
    asio::io_context& ctx) const {
    
    asio::ip::tcp::resolver resolver(ctx);
    std::vector<asio::ip::tcp::endpoint> endpoints;
    
    try {
        if (hostname_.empty()) {
            // Bind to all interfaces
            if (family_ == AddressFamily::IPv4) {
                endpoints.emplace_back(asio::ip::tcp::v4(), port_);
            } else if (family_ == AddressFamily::IPv6) {
                endpoints.emplace_back(asio::ip::tcp::v6(), port_);
            } else {
                // UNSPEC - add both
                endpoints.emplace_back(asio::ip::tcp::v4(), port_);
                endpoints.emplace_back(asio::ip::tcp::v6(), port_);
            }
        } else {
            // Resolve hostname
            std::string port_str = std::to_string(port_);
            auto results = co_await resolver.async_resolve(hostname_, port_str, asio::use_awaitable);
            
            for (const auto& entry : results) {
                endpoints.push_back(entry.endpoint());
            }
        }
    } catch (const std::exception&) {
        // Return empty vector on resolution failure
    }
    
    co_return endpoints;
}

asio::awaitable<std::vector<asio::ip::tcp::endpoint>> RemoteEndpoint::resolve(
    asio::io_context& ctx) const {
    
    asio::ip::tcp::resolver resolver(ctx);
    std::vector<asio::ip::tcp::endpoint> endpoints;
    
    try {
        std::string port_str = std::to_string(port_);
        auto results = co_await resolver.async_resolve(hostname_, port_str, asio::use_awaitable);
        
        for (const auto& entry : results) {
            endpoints.push_back(entry.endpoint());
        }
    } catch (const std::exception&) {
        // Return empty vector on resolution failure
    }
    
    co_return endpoints;
}

}