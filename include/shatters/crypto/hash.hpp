#pragma once

#include <shatters/crypto/secure_memory.hpp>
#include <shatters/constants.hpp>

namespace shatters::crypto {

// BLAKE2b-256 (unkeyed)
ByteArray<kHashSize> blake2b(const uint8_t* data, size_t len);

// BLAKE2b-256 (keyed)
ByteArray<kHashSize> blake2b_keyed(const uint8_t* data, size_t len,
                                   const uint8_t* key, size_t key_len);

} // namespace shatters::crypto
