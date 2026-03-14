#include <shatters/crypto/kdf.hpp>

#include <sodium.h>

#include <cstring>

namespace shatters::crypto
{

Result<KdfKey> hkdf_extract(ByteSpan salt, ByteSpan ikm)
{
    KdfKey prk{};

    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, salt.data(), salt.size());
    crypto_auth_hmacsha256_update(&state, ikm.data(), ikm.size());
    crypto_auth_hmacsha256_final(&state, prk.data());

    sodium_memzero(&state, sizeof(state));
    return prk;
}

Result<Bytes> hkdf_expand(ByteSpan prk, ByteSpan info, size_t length)
{
    if (prk.size() < HMAC_SHA256_SIZE)
        return Error{ErrorCode::InvalidArgument, "prk must be at least 32 bytes"};

    constexpr size_t hash_len = HMAC_SHA256_SIZE;
    const size_t n = (length + hash_len - 1) / hash_len;

    if (n > 255)
        return Error{ErrorCode::InvalidArgument, "hkdf expand: output too long"};

    Bytes okm;
    okm.reserve(length);

    std::array<uint8_t, HMAC_SHA256_SIZE> t{};
    size_t t_len = 0;

    for (size_t i = 1; i <= n; ++i)
    {
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());

        if (t_len > 0)
            crypto_auth_hmacsha256_update(&state, t.data(), t_len);

        crypto_auth_hmacsha256_update(&state, info.data(), info.size());

        const uint8_t counter = static_cast<uint8_t>(i);
        crypto_auth_hmacsha256_update(&state, &counter, 1);
        crypto_auth_hmacsha256_final(&state, t.data());

        sodium_memzero(&state, sizeof(state));
        t_len = hash_len;

        const size_t remaining = length - okm.size();
        const size_t to_copy   = (remaining < hash_len) ? remaining : hash_len;
        okm.insert(okm.end(), t.data(), t.data() + to_copy);
    }

    sodium_memzero(t.data(), t.size());
    return okm;
}

Result<Bytes> hkdf(ByteSpan salt, ByteSpan ikm, ByteSpan info, size_t length)
{
    auto prk_result = hkdf_extract(salt, ikm);
    SHATTERS_TRY(prk_result);

    const auto& prk = prk_result.value();
    return hkdf_expand({prk.data(), prk.size()}, info, length);
}

Result<ChainKeyPair> chain_kdf(const KdfKey& chain_key)
{
    ChainKeyPair result{};

    static constexpr uint8_t CHAIN_CONSTANT = 0x01;
    static constexpr uint8_t MSG_CONSTANT   = 0x02;

    crypto_auth_hmacsha256_state state;

    crypto_auth_hmacsha256_init(&state, chain_key.data(), chain_key.size());
    crypto_auth_hmacsha256_update(&state, &CHAIN_CONSTANT, 1);
    crypto_auth_hmacsha256_final(&state, result.chain_key.data());

    crypto_auth_hmacsha256_init(&state, chain_key.data(), chain_key.size());
    crypto_auth_hmacsha256_update(&state, &MSG_CONSTANT, 1);
    crypto_auth_hmacsha256_final(&state, result.message_key.data());

    sodium_memzero(&state, sizeof(state));
    return result;
}

Result<RootKeyPair> root_kdf(const KdfKey& root_key, ByteSpan dh_output)
{
    static constexpr std::string_view info = "shatters-ratchet";
    const ByteSpan info_span{reinterpret_cast<const uint8_t*>(info.data()), info.size()};

    auto derived = hkdf(
        {root_key.data(), root_key.size()},
        dh_output,
        info_span,
        64 
    );
    SHATTERS_TRY(derived);

    const auto& okm = derived.value();
    RootKeyPair result{};
    std::memcpy(result.root_key.data(), okm.data(), KDF_KEY_SIZE);
    std::memcpy(result.chain_key.data(), okm.data() + KDF_KEY_SIZE, KDF_KEY_SIZE);

    return result;
}

Result<KdfKey> derive_key_from_password(const std::string& password, ByteSpan salt)
{
    if (salt.size() != ARGON2_SALT_SIZE)
        return Error{ErrorCode::InvalidArgument, "salt must be 16 bytes"};

    KdfKey key{};

    if (crypto_pwhash(
            key.data(), key.size(),
            password.c_str(), password.size(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return Error{ErrorCode::CryptoError, "argon2id key derivation failed (out of memory?)"};
    }

    return key;
}

std::array<uint8_t, ARGON2_SALT_SIZE> generate_salt()
{
    std::array<uint8_t, ARGON2_SALT_SIZE> salt{};
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

}