#pragma once

#include <shatters/types.hpp>

#include <array>
#include <cstdint>

namespace shatters::crypto
{

constexpr size_t AEAD_KEY_SIZE   = 32;
constexpr size_t AEAD_NONCE_SIZE = 24;
constexpr size_t AEAD_TAG_SIZE   = 16;

using AeadKey   = std::array<uint8_t, AEAD_KEY_SIZE>;
using AeadNonce = std::array<uint8_t, AEAD_NONCE_SIZE>;

Result<Bytes> aead_encrypt(
    ByteSpan plaintext,
    ByteSpan ad,
    const AeadNonce& nonce,
    const AeadKey& key
);

Result<Bytes> aead_decrypt(
    ByteSpan ciphertext,
    ByteSpan ad,
    const AeadNonce& nonce,
    const AeadKey& key
);

Result<Bytes> aead_seal(
    ByteSpan plaintext,
    ByteSpan ad,
    const AeadKey& key
);

Result<Bytes> aead_open(
    ByteSpan sealed,
    ByteSpan ad,
    const AeadKey& key
);

AeadNonce generate_nonce();

AeadNonce nonce_from_counter(uint32_t counter);

}