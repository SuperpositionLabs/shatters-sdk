#pragma once

#include <shatters/crypto/secure_memory.hpp>
#include <shatters/constants.hpp>

#include <optional>
#include <vector>

namespace shatters::crypto {

using AeadNonce = ByteArray<kAeadNonceSize>;

// XChaCha20-Poly1305 encrypt. Returns ciphertext || tag(16B).
std::vector<uint8_t> aead_encrypt(
    const SecureArray<kKeySize>& key,
    const AeadNonce& nonce,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* aad = nullptr, size_t aad_len = 0);

// XChaCha20-Poly1305 decrypt. Returns plaintext, or nullopt on auth failure.
std::optional<std::vector<uint8_t>> aead_decrypt(
    const SecureArray<kKeySize>& key,
    const AeadNonce& nonce,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* aad = nullptr, size_t aad_len = 0);

// Pad to target_size: [4B big-endian length][data][random fill].
std::vector<uint8_t> pad(const uint8_t* data, size_t data_len,
                         size_t target_size = kMaxBlobSize);

// Extract original data from padded buffer.
std::optional<std::vector<uint8_t>> unpad(const uint8_t* padded, size_t padded_len);

} // namespace shatters::crypto
