#pragma once

#include <shatters/crypto/secure_memory.hpp>
#include <sodium.h>

namespace shatters::crypto {

inline void random_bytes(uint8_t* buf, size_t len) {
    randombytes_buf(buf, len);
}

template <size_t N>
ByteArray<N> random_byte_array() {
    ByteArray<N> buf;
    randombytes_buf(buf.data(), N);
    return buf;
}

template <size_t N>
SecureArray<N> random_secure_array() {
    SecureArray<N> buf;
    randombytes_buf(buf.data(), N);
    return buf;
}

} // namespace shatters::crypto
