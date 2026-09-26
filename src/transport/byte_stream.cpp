#include "transport/byte_stream.h"
#include "transport/io_error.h"

#ifdef TAPS_WITH_TLS
#include <asio/ssl/error.hpp>
#endif

namespace taps {

TAPSError read_failure(const std::error_code& ec) {
#ifdef TAPS_WITH_TLS
    if (ec == asio::ssl::error::stream_truncated)
        return TAPSError{ErrorEvent::RECEIVE_ERROR, ErrorReason::PROTOCOL_FAILED,
                         "TLS stream truncated: peer closed without close_notify"};
#endif
    return io_error(ErrorEvent::CONNECTION_ERROR, ec);
}

}  // namespace taps
