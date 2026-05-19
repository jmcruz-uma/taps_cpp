#include "taps/taps_api.h"
namespace taps{

// ============================================================================
// TransportProperties Implementation
// ============================================================================

bool TransportProperties::requires_reliable_transport() const noexcept {
    auto reliability = get(PropertyKey::RELIABILITY);
    return reliability == SelectionProperty::REQUIRE || reliability == SelectionProperty::PREFER;
}

bool TransportProperties::requires_ordered_delivery() const noexcept {
    auto ordering = get(PropertyKey::PRESERVE_ORDER);
    return ordering == SelectionProperty::REQUIRE || ordering == SelectionProperty::PREFER;
}

bool TransportProperties::requires_message_boundaries() const noexcept {
    auto boundaries = get(PropertyKey::PRESERVE_MSG_BOUNDARIES);
    return boundaries == SelectionProperty::REQUIRE || boundaries == SelectionProperty::PREFER;
}

Direction TransportProperties::get_direction() const noexcept {
    //auto direction_prop = get(PropertyKey::DIRECTION);
    // Default to bidirectional if not specified
    return Direction::BIDIRECTIONAL;
}


}