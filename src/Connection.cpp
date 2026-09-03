#include "taps/taps_api.h"

namespace taps {

// Framing is applied on the wire by the transport-specific receive path; this
// helper just wraps an already-decoded payload in an owning Message.
Result<Message> Connection::make_message(std::vector<uint8_t>&& buffer) {
    return Message(std::move(buffer));
}

}
