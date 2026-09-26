#pragma once

#include "buffer/block.h"

#include <cstddef>
#include <memory>
#include <memory_resource>

namespace taps {

struct MessageMemoryConfig;

// ============================================================================
// MessageBlockPool
// ============================================================================
//
// How one Connection's receive path (or one UDP Listener's) obtains the
// fixed-size blocks that received message data lands in. The memory comes from
// the message memory resource (MessageMemoryConfig); recycling, if any, is the
// resource's. The pool adds only the optional cap on live blocks, which the
// receive path uses as backpressure (acquire() fails at the cap).
//
// The blocks do not refer to the pool, so they may outlive it; the cap counter
// is shared with them for that reason. No locks: the counter is atomic, and the
// resource provides whatever thread safety the application chose.
class MessageBlockPool {
public:
    explicit MessageBlockPool(const MessageMemoryConfig& config);

    // A fresh block with an empty live window [0, 0), or an invalid BlockRef at
    // the live-block cap.
    BlockRef acquire();

    std::size_t block_size() const noexcept { return block_size_; }
    bool        at_capacity() const noexcept;
    std::size_t live_blocks() const noexcept;   // 0 when there is no cap
    std::pmr::memory_resource* resource() const noexcept { return resource_; }

private:
    std::pmr::memory_resource*              resource_;
    std::size_t                             block_size_;
    std::size_t                             max_live_blocks_;   // 0 = no cap
    std::shared_ptr<DataBlock::LiveCounter> live_;              // only with a cap
};

}  // namespace taps
