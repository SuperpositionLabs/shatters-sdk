#include <shatters/crypto/kdf.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstring>

namespace shatters::crypto {

namespace {

void hkdf_extract(uint8_t prk[64],
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* ikm, size_t ikm_len) {
    crypto_auth_hmacsha512_state state;
    if (salt == nullptr || salt_len == 0) {
        const uint8_t zero_salt[64] = {};
        crypto_auth_hmacsha512_init(&state, zero_salt, 64);
    } else {
        crypto_auth_hmacsha512_init(&state, salt, salt_len);
    }
    crypto_auth_hmacsha512_update(&state, ikm, ikm_len);
    crypto_auth_hmacsha512_final(&state, prk);
    sodium_memzero(&state, sizeof(state));
}

void hkdf_expand(uint8_t* out, size_t out_len,
                 const uint8_t prk[64],
                 const uint8_t* info, size_t info_len) {
    uint8_t t[64] = {};
    size_t t_len = 0;
    size_t offset = 0;

    for (uint8_t i = 1; offset < out_len; ++i) {
        crypto_auth_hmacsha512_state state;
        crypto_auth_hmacsha512_init(&state, prk, 64);
        if (t_len > 0) {
            crypto_auth_hmacsha512_update(&state, t, t_len);
        }
        if (info_len > 0) {
            crypto_auth_hmacsha512_update(&state, info, info_len);
        }
        crypto_auth_hmacsha512_update(&state, &i, 1);
        crypto_auth_hmacsha512_final(&state, t);
        sodium_memzero(&state, sizeof(state));
        t_len = 64;

        const size_t to_copy = std::min<size_t>(64, out_len - offset);
        std::memcpy(out + offset, t, to_copy);
        offset += to_copy;
    }
    sodium_memzero(t, 64);
}

} // anonymous namespace

void hkdf_sha512(uint8_t* out, size_t out_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* info, size_t info_len) {
    uint8_t prk[64];
    hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    hkdf_expand(out, out_len, prk, info, info_len);
    sodium_memzero(prk, 64);
}

} // namespace shatters::crypto
