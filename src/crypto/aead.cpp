#include <shatters/crypto/aead.hpp>
#include <sodium.h>

#include <cstring>
#include <stdexcept>

namespace shatters::crypto {

std::vector<uint8_t> aead_encrypt(
    const SecureArray<kKeySize>& key,
    const AeadNonce& nonce,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* aad, size_t aad_len) {

    std::vector<uint8_t> ct(plaintext_len + kAeadTagSize);
    unsigned long long ct_len = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len,
        plaintext, plaintext_len,
        aad, aad_len,
        nullptr, nonce.data(), key.data());

    ct.resize(static_cast<size_t>(ct_len));
    return ct;
}

std::optional<std::vector<uint8_t>> aead_decrypt(
    const SecureArray<kKeySize>& key,
    const AeadNonce& nonce,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* aad, size_t aad_len) {

    if (ciphertext_len < kAeadTagSize) {
        return std::nullopt;
    }

    std::vector<uint8_t> pt(ciphertext_len - kAeadTagSize);
    unsigned long long pt_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len,
            nullptr,
            ciphertext, ciphertext_len,
            aad, aad_len,
            nonce.data(), key.data()) != 0) {
        return std::nullopt;
    }

    pt.resize(static_cast<size_t>(pt_len));
    return pt;
}

std::vector<uint8_t> pad(const uint8_t* data, size_t data_len,
                         size_t target_size) {
    if (data_len + 4 > target_size) {
        throw std::invalid_argument("Data too large for target padding size");
    }

    std::vector<uint8_t> padded(target_size);

    const auto len = static_cast<uint32_t>(data_len);
    padded[0] = static_cast<uint8_t>(len >> 24);
    padded[1] = static_cast<uint8_t>(len >> 16);
    padded[2] = static_cast<uint8_t>(len >> 8);
    padded[3] = static_cast<uint8_t>(len);

    std::memcpy(padded.data() + 4, data, data_len);

    const size_t pad_start = 4 + data_len;
    randombytes_buf(padded.data() + pad_start, target_size - pad_start);

    return padded;
}

std::optional<std::vector<uint8_t>> unpad(const uint8_t* padded, size_t padded_len) {
    if (padded_len < 4) {
        return std::nullopt;
    }

    const uint32_t data_len =
        (static_cast<uint32_t>(padded[0]) << 24) |
        (static_cast<uint32_t>(padded[1]) << 16) |
        (static_cast<uint32_t>(padded[2]) << 8) |
         static_cast<uint32_t>(padded[3]);

    if (data_len + 4 > padded_len) {
        return std::nullopt;
    }

    return std::vector<uint8_t>(padded + 4, padded + 4 + data_len);
}

} // namespace shatters::crypto
