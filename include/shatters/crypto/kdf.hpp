#pragma once

#include <cstddef>
#include <cstdint>

namespace shatters::crypto {

// HKDF-SHA-512 (RFC 5869): Extract-then-Expand.
// Writes out_len bytes of derived key material to out.
// salt may be nullptr (treated as 64 zero bytes per RFC).
void hkdf_sha512(uint8_t* out, size_t out_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* info, size_t info_len);

} // namespace shatters::crypto
