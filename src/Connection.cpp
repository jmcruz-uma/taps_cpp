#include "taps/taps_api.h"

namespace taps {

Result<Message> Connection::make_message(std::vector<uint8_t>&& buffer) {
    if (framer_) {
        std::vector<Message> messages;
        auto consumed = framer_->parse_stream(std::span(buffer), messages);
        if (messages.empty()) {
            return std::unexpected(TAPSError(
                ErrorType::FRAMING_ERROR,
                "No complete message in received data"
            ));
        }
        (void)consumed;
        return std::move(messages[0]);
    } else {
        return Message(std::move(buffer));
    }
}

}
