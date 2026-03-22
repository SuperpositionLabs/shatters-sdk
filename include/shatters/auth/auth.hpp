#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/types.hpp>

#include <cstdint>

namespace shatters::auth
{

constexpr size_t AUTH_DOMAIN_SIZE = 17;
constexpr size_t CHAN_DOMAIN_SIZE = 17;
constexpr size_t PROOF_SIZE      = 64;

inline constexpr uint8_t AUTH_DOMAIN[AUTH_DOMAIN_SIZE] = {
    '$','h','a','t','t','e','r','$','-','a','u','t','h','-','v','1','\0'
};
static_assert(AUTH_DOMAIN[16] == '\0');

inline constexpr uint8_t CHAN_DOMAIN[CHAN_DOMAIN_SIZE] = {
    '$','h','a','t','t','e','r','$','-','c','h','a','n','-','v','1','\0'
};
static_assert(CHAN_DOMAIN[16] == '\0');

[[nodiscard]]
Result<Bytes> build_auth_payload(const crypto::IdentityKeyPair& kp);

[[nodiscard]]
Result<Bytes> build_channel_proof(
    const crypto::IdentityKeyPair& kp,
    const Channel& channel,
    ByteSpan inner_payload = {});

}
