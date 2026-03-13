#include <shatters/init.hpp>
#include <sodium.h>

namespace shatters {

bool init() {
    return sodium_init() >= 0;
}

}
