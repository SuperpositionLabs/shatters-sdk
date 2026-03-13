#include <shatters/crypto/hash.hpp>
#include <sodium.h>

namespace shatters::crypto {

ByteArray<kHashSize> blake2b(const uint8_t* data, size_t len) {
    ByteArray<kHashSize> out;
    crypto_generichash(out.data(), kHashSize, data, len, nullptr, 0);
    return out;
}

ByteArray<kHashSize> blake2b_keyed(const uint8_t* data, size_t len,
                                   const uint8_t* key, size_t key_len) {
    ByteArray<kHashSize> out;
    crypto_generichash(out.data(), kHashSize, data, len, key, key_len);
    return out;
}

} // namespace shatters::crypto
