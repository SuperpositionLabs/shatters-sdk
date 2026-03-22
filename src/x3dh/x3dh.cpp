#include <shatters/x3dh/x3dh.hpp>
#include <shatters/crypto/kdf.hpp>

#include <sodium.h>

#include <cstring>

namespace shatters::x3dh
{

namespace
{
    void write_u16_be(uint8_t* dst, uint16_t val)
    {
        dst[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
        dst[1] = static_cast<uint8_t>( val       & 0xFF);
    }

    uint16_t read_u16_be(const uint8_t* src)
    {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(src[0]) << 8) | src[1]);
    }

    void write_u32_be(uint8_t* dst, uint32_t val)
    {
        dst[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
        dst[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
        dst[2] = static_cast<uint8_t>((val >>  8) & 0xFF);
        dst[3] = static_cast<uint8_t>( val        & 0xFF);
    }

    uint32_t read_u32_be(const uint8_t* src)
    {
        return (static_cast<uint32_t>(src[0]) << 24) |
               (static_cast<uint32_t>(src[1]) << 16) |
               (static_cast<uint32_t>(src[2]) <<  8) |
                static_cast<uint32_t>(src[3]);
    }

    constexpr std::string_view X3DH_INFO = "$hatter$-x3dh";

    Result<crypto::KdfKey> derive_sk(
        const crypto::SharedSecret& dh1,
        const crypto::SharedSecret& dh2,
        const crypto::SharedSecret& dh3,
        const crypto::SharedSecret* dh4)
    {
        size_t ikm_len = 32 * 3 + (dh4 ? 32 : 0);
        Bytes ikm(ikm_len);
        size_t pos = 0;
        std::memcpy(ikm.data() + pos, dh1.data(), 32); pos += 32;
        std::memcpy(ikm.data() + pos, dh2.data(), 32); pos += 32;
        std::memcpy(ikm.data() + pos, dh3.data(), 32); pos += 32;
        if (dh4)
        {
            std::memcpy(ikm.data() + pos, dh4->data(), 32);
        }

        std::array<uint8_t, 32> salt{};

        ByteSpan info_span{
            reinterpret_cast<const uint8_t*>(X3DH_INFO.data()),
            X3DH_INFO.size()};

        auto derived = crypto::hkdf(salt, ikm, info_span, 32);
        SHATTERS_TRY(derived);

        crypto::KdfKey sk{};
        std::memcpy(sk.data(), derived.value().data(), 32);

        sodium_memzero(ikm.data(), ikm.size());
        return sk;
    }
}

Bytes serialize_bundle(const PreKeyBundle& bundle)
{
    const auto n = static_cast<uint16_t>(bundle.one_time_prekeys.size());
    const size_t total = 32 + 32 + 64 + 2 + n * (4 + 32);

    Bytes out(total);
    size_t pos = 0;

    std::memcpy(out.data() + pos, bundle.identity_key.data(), 32);      pos += 32;
    std::memcpy(out.data() + pos, bundle.signed_prekey.data(), 32);     pos += 32;
    std::memcpy(out.data() + pos, bundle.signed_prekey_sig.data(), 64); pos += 64;
    write_u16_be(out.data() + pos, n);                                  pos += 2;

    for (const auto& opk : bundle.one_time_prekeys)
    {
        write_u32_be(out.data() + pos, opk.id);                         pos += 4;
        std::memcpy(out.data() + pos, opk.public_key.data(), 32);       pos += 32;
    }

    return out;
}

Result<PreKeyBundle> deserialize_bundle(ByteSpan data)
{
    constexpr size_t MIN_SIZE = 32 + 32 + 64 + 2;
    if (data.size() < MIN_SIZE)
        return Error{ErrorCode::ProtocolError, "bundle too short"};

    PreKeyBundle bundle{};
    size_t pos = 0;

    std::memcpy(bundle.identity_key.data(), data.data() + pos, 32);      pos += 32;
    std::memcpy(bundle.signed_prekey.data(), data.data() + pos, 32);     pos += 32;
    std::memcpy(bundle.signed_prekey_sig.data(), data.data() + pos, 64); pos += 64;

    uint16_t n = read_u16_be(data.data() + pos); pos += 2;

    if (data.size() < MIN_SIZE + n * (4 + 32))
        return Error{ErrorCode::ProtocolError, "bundle truncated"};

    bundle.one_time_prekeys.resize(n);
    for (uint16_t i = 0; i < n; ++i)
    {
        bundle.one_time_prekeys[i].id = read_u32_be(data.data() + pos); pos += 4;
        std::memcpy(bundle.one_time_prekeys[i].public_key.data(), data.data() + pos, 32);
        pos += 32;
    }

    return bundle;
}

Bytes serialize_initial(const InitialMessage& msg)
{
    Bytes out(INITIAL_MSG_HEADER_SIZE + msg.ciphertext.size());
    size_t pos = 0;

    std::memcpy(out.data() + pos, msg.sender_identity_key.data(), 32); pos += 32;
    std::memcpy(out.data() + pos, msg.ephemeral_key.data(), 32);       pos += 32;
    write_u32_be(out.data() + pos, msg.opk_id);                        pos += 4;

    if (!msg.ciphertext.empty())
        std::memcpy(out.data() + pos, msg.ciphertext.data(), msg.ciphertext.size());

    return out;
}

Result<InitialMessage> deserialize_initial(ByteSpan data)
{
    if (data.size() < INITIAL_MSG_HEADER_SIZE)
        return Error{ErrorCode::ProtocolError, "initial message too short"};

    InitialMessage msg{};
    size_t pos = 0;

    std::memcpy(msg.sender_identity_key.data(), data.data() + pos, 32); pos += 32;
    std::memcpy(msg.ephemeral_key.data(), data.data() + pos, 32);       pos += 32;
    msg.opk_id = read_u32_be(data.data() + pos);                        pos += 4;

    if (pos < data.size())
        msg.ciphertext.assign(data.data() + pos, data.data() + data.size());

    return msg;
}

Result<X3DHResult> initiate(
    const crypto::IdentityKeyPair& our_identity,
    const PreKeyBundle& their_bundle)
{
    auto verify = crypto::verify_signature(
        their_bundle.signed_prekey,
        their_bundle.signed_prekey_sig,
        their_bundle.identity_key
    );
    SHATTERS_TRY(verify);

    auto their_ik_x = crypto::ed25519_pk_to_x25519(their_bundle.identity_key);
    SHATTERS_TRY(their_ik_x);

    auto ek = crypto::X25519KeyPair::generate();
    SHATTERS_TRY(ek);

    auto dh1 = crypto::x25519_dh(our_identity.x25519_secret(), their_bundle.signed_prekey);
    SHATTERS_TRY(dh1);

    auto dh2 = crypto::x25519_dh(ek.value().secret_key(), their_ik_x.value());
    SHATTERS_TRY(dh2);

    auto dh3 = crypto::x25519_dh(ek.value().secret_key(), their_bundle.signed_prekey);
    SHATTERS_TRY(dh3);

    std::optional<crypto::SharedSecret> dh4;
    uint32_t opk_id = NO_OPK;

    if (!their_bundle.one_time_prekeys.empty())
    {
        const auto& chosen_opk = their_bundle.one_time_prekeys[0];
        auto dh4_r = crypto::x25519_dh(
            ek.value().secret_key(),
            chosen_opk.public_key
        );
        SHATTERS_TRY(dh4_r);
        dh4 = std::move(dh4_r).take_value();
        opk_id = chosen_opk.id;
    }

    auto sk = derive_sk(
        dh1.value(), dh2.value(), dh3.value(),
        dh4.has_value() ? &dh4.value() : nullptr
    );
    SHATTERS_TRY(sk);

    return X3DHResult
    {
        .shared_secret   = sk.value(),
        .ephemeral_public = ek.value().public_key(),
        .opk_id          = opk_id,
    };
}

Result<crypto::KdfKey> respond(
    const crypto::IdentityKeyPair& our_identity,
    const crypto::X25519KeyPair&   our_signed_prekey,
    const crypto::X25519KeyPair*   our_one_time_prekey,
    const crypto::PublicKey&       their_identity_key,
    const crypto::X25519Public&    their_ephemeral_key)
{
    auto their_ik_x = crypto::ed25519_pk_to_x25519(their_identity_key);
    SHATTERS_TRY(their_ik_x);

    auto dh1 = crypto::x25519_dh(our_signed_prekey.secret_key(), their_ik_x.value());
    SHATTERS_TRY(dh1);

    auto dh2 = crypto::x25519_dh(our_identity.x25519_secret(), their_ephemeral_key);
    SHATTERS_TRY(dh2);

    auto dh3 = crypto::x25519_dh(our_signed_prekey.secret_key(), their_ephemeral_key);
    SHATTERS_TRY(dh3);

    std::optional<crypto::SharedSecret> dh4;
    if (our_one_time_prekey)
    {
        auto dh4_r = crypto::x25519_dh(
            our_one_time_prekey->secret_key(),
            their_ephemeral_key
        );
        SHATTERS_TRY(dh4_r);
        dh4 = std::move(dh4_r).take_value();
    }

    return derive_sk(
        dh1.value(), dh2.value(), dh3.value(),
        dh4.has_value() ? &dh4.value() : nullptr
    );
}

}