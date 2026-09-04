#include "buffer/block_pool.h"

namespace taps {

// DataBlock::release — declared in block.h, defined here where the abstract
// BlockPool (specifically its recycle()) is complete. Dispatches virtually, so
// this needs no knowledge of which concrete strategy actually owns the block.
void DataBlock::release() noexcept {
    if (refcount_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        if (pool_)
            pool_->recycle(this);
        else
            delete this;
    }
}

}  // namespace taps
