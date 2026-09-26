#pragma once

#include "taps/taps_api.h"   // TAPSError, ErrorEvent, ErrorReason

#include <asio/error.hpp>

#include <string>
#include <system_error>

namespace taps {

// Maps an I/O error code to an RFC 9623 Appendix B reason (or one of the
// implementation's own). Codes without a more specific reason are PROTOCOL_FAILED.
inline ErrorReason reason_from(const std::error_code& ec) noexcept {
    if (ec == asio::error::connection_reset || ec == asio::error::connection_aborted ||
        ec == asio::error::broken_pipe)
        return ErrorReason::CONNECTION_ABORTED;
    if (ec == asio::error::timed_out)
        return ErrorReason::TIMEOUT;
    if (ec == asio::error::operation_aborted)
        return ErrorReason::LOCAL_ABORT;
    if (ec == asio::error::message_size)
        return ErrorReason::MESSAGE_TOO_LARGE;
    if (ec == asio::error::address_in_use)
        return ErrorReason::LOCAL_ENDPOINT_UNAVAILABLE;
    if (ec == asio::error::access_denied)
        return ErrorReason::POLICY_PROHIBITED;
    if (ec == asio::error::no_descriptors || ec == asio::error::no_buffer_space ||
        ec == asio::error::no_memory)
        return ErrorReason::RESOURCE_EXHAUSTED;
    return ErrorReason::PROTOCOL_FAILED;
}

inline TAPSError io_error(ErrorEvent event, const std::error_code& ec) {
    return TAPSError{event, reason_from(ec), ec.message()};
}

}  // namespace taps
