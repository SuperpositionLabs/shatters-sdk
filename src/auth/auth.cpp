#include <shatters/auth/auth.hpp>

#include <chrono>
#include <cstring>

namespace shatters::auth
{

namespace
{
    void write_u64_be(uint8_t* dst, uint64_t val)
    {
        dst[0] = static_cast<uint8_t>((val >> 56) & 0xFF);
        dst[1] = static_cast<uint8_t>((val >> 48) & 0xFF);
        dst[2] = static_cast<uint8_t>((val >> 40) & 0xFF);
        dst[3] = static_cast<uint8_t>((val >> 32) & 0xFF);
        dst[4] = static_cast<uint8_t>((val >> 24) & 0xFF);
        dst[5] = static_cast<uint8_t>((val >> 16) & 0xFF);
        dst[6] = static_cast<uint8_t>((val >>  8) & 0xFF);
        dst[7] = static_cast<uint8_t>( val        & 0xFF);
    }
}

Result<Bytes> build_auth_payload(const crypto::IdentityKeyPair& kp)
{
    const auto& pubkey = kp.ed25519_public();

    auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());

    Bytes to_sign(AUTH_DOMAIN_SIZE + 32 + 8);
    size_t pos = 0;
    std::memcpy(to_sign.data() + pos, AUTH_DOMAIN, AUTH_DOMAIN_SIZE);  pos += AUTH_DOMAIN_SIZE;
    std::memcpy(to_sign.data() + pos, pubkey.data(), 32);             pos += 32;
    write_u64_be(to_sign.data() + pos, now_ms);

    auto sig = kp.sign(to_sign);
    SHATTERS_TRY(sig);

    Bytes payload(32 + 8 + 64);
    pos = 0;
    std::memcpy(payload.data() + pos, pubkey.data(), 32);           pos += 32;
    write_u64_be(payload.data() + pos, now_ms);                     pos += 8;
    std::memcpy(payload.data() + pos, sig.value().data(), 64);

    return payload;
}

Result<Bytes> build_channel_proof(
    const crypto::IdentityKeyPair& kp,
    const Channel& channel,
    ByteSpan inner_payload)
{
    Bytes to_sign(CHAN_DOMAIN_SIZE + CHANNEL_SIZE);
    std::memcpy(to_sign.data(), CHAN_DOMAIN, CHAN_DOMAIN_SIZE);
    std::memcpy(to_sign.data() + CHAN_DOMAIN_SIZE, channel.data(), CHANNEL_SIZE);

    auto sig = kp.sign(to_sign);
    SHATTERS_TRY(sig);

    Bytes out(PROOF_SIZE + inner_payload.size());
    std::memcpy(out.data(), sig.value().data(), PROOF_SIZE);
    if (!inner_payload.empty())
        std::memcpy(out.data() + PROOF_SIZE, inner_payload.data(), inner_payload.size());

    return out;
}

}
