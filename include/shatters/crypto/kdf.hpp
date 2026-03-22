#pragma once

#include <shatters/types.hpp>

#include <array>
#include <cstdint>

namespace shatters::crypto
{

constexpr size_t KDF_KEY_SIZE    = 32;
constexpr size_t KDF_SALT_SIZE   = 32;
constexpr size_t HMAC_SHA256_SIZE = 32;

using KdfKey = std::array<uint8_t, KDF_KEY_SIZE>;

Result<KdfKey> hkdf_extract(ByteSpan salt, ByteSpan ikm);
Result<Bytes>  hkdf_expand(ByteSpan prk, ByteSpan info, size_t length);
Result<Bytes>  hkdf(ByteSpan salt, ByteSpan ikm, ByteSpan info, size_t length);

struct ChainKeyPair
{
    KdfKey chain_key;
    KdfKey message_key;
};

Result<ChainKeyPair> chain_kdf(const KdfKey& chain_key);

struct RootKeyPair
{
    KdfKey root_key;
    KdfKey chain_key;
};

Result<RootKeyPair> root_kdf(const KdfKey& root_key, ByteSpan dh_output);

constexpr size_t ARGON2_SALT_SIZE = 16;

Result<KdfKey> derive_key_from_password(
    const std::string& password,
    ByteSpan salt
);

std::array<uint8_t, ARGON2_SALT_SIZE> generate_salt();

constexpr size_t NONCE_PREFIX_SIZE = 20;

Result<std::array<uint8_t, NONCE_PREFIX_SIZE>> derive_nonce_prefix(const KdfKey& chain_key);

}