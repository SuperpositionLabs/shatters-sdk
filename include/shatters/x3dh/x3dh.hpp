#pragma once

#include <shatters/crypto/kdf.hpp>
#include <shatters/crypto/keys.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <vector>

namespace shatters::x3dh
{
    struct PreKeyBundle
    {
        crypto::PublicKey         identity_key;
        crypto::X25519Public      signed_prekey;
        crypto::Signature         signed_prekey_sig;
        std::vector<crypto::X25519Public> one_time_prekeys;
    };

    [[nodiscard]] Bytes                serialize_bundle(const PreKeyBundle& bundle);
    [[nodiscard]] Result<PreKeyBundle> deserialize_bundle(ByteSpan data);

    struct X3DHResult
    {
        crypto::KdfKey          shared_secret;
        crypto::X25519Public    ephemeral_public; 
        uint32_t                opk_id;
    };

    struct InitialMessage
    {
        crypto::PublicKey     sender_identity_key;
        crypto::X25519Public ephemeral_key;
        uint32_t             opk_id;
        Bytes                ciphertext;
    };

    constexpr size_t INITIAL_MSG_HEADER_SIZE = 32 + 32 + 4;
    constexpr uint32_t NO_OPK = 0xFFFFFFFF;

    [[nodiscard]] Bytes                  serialize_initial(const InitialMessage& msg);
    [[nodiscard]] Result<InitialMessage> deserialize_initial(ByteSpan data);

    [[nodiscard]] Result<X3DHResult> initiate(
        const crypto::IdentityKeyPair& our_identity,
        const PreKeyBundle& their_bundle
    );

    [[nodiscard]] Result<crypto::KdfKey> respond(
        const crypto::IdentityKeyPair& our_identity,
        const crypto::X25519KeyPair&   our_signed_prekey,
        const crypto::X25519KeyPair*   our_one_time_prekey,
        const crypto::PublicKey&       their_identity_key,
        const crypto::X25519Public&    their_ephemeral_key
    );

}