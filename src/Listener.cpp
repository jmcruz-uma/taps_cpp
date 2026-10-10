#include "taps/taps_api.h"
#include "new_connection_limit.h"

#include <memory>

namespace taps {

Listener::Listener() : new_connection_limit_(std::make_shared<NewConnectionLimit>()) {}

Listener::~Listener() = default;

void Listener::set_new_connection_limit(std::size_t limit) {
    new_connection_limit_->set(limit);
    new_connection_limit_changed();
}

}  // namespace taps
