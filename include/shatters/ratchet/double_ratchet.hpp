#pragma once

#include <shatters/crypto/aead.hpp>
#include <shatters/crypto/kdf.hpp>
#include <shatters/crypto/keys.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <map>
#include <utility>

namespace shatters::ratchet
{
    constexpr size_t   MAX_SKIP = 100;
    constexpr uint32_t COUNTER_MAX = 0xFFFFFFFF;

    constexpr size_t RATCHET_HEADER_SIZE = 32 + 4 + 4;

    struct MessageHeader
    {
        crypto::X25519Public dh_public;
        uint32_t             message_number;
        uint32_t             previous_chain_length;
    };

    [[nodiscard]] Bytes                serialize_header(const MessageHeader& header);
    [[nodiscard]] Result<MessageHeader> deserialize_header(ByteSpan data);

    struct SkippedKeyIndex
    {
        crypto::X25519Public dh_public;
        uint32_t             message_number;

        bool operator<(const SkippedKeyIndex& other) const
        {
            if (dh_public != other.dh_public)
                return dh_public < other.dh_public;
            return message_number < other.message_number;
        }
    };

    struct RatchetState
    {
        crypto::KdfKey       root_key{};
        crypto::X25519Public dh_self_public{};
        crypto::X25519Secret dh_self_secret;
        crypto::X25519Public dh_remote_public{};
        crypto::KdfKey       send_chain_key{};
        crypto::KdfKey       recv_chain_key{};
        uint32_t             send_count = 0;
        uint32_t             recv_count = 0;
        uint32_t             prev_send_count = 0;

        std::map<SkippedKeyIndex, crypto::KdfKey> skipped_keys;
    };

    [[nodiscard]] Bytes               serialize_state(const RatchetState& state);
    [[nodiscard]] Result<RatchetState> deserialize_state(ByteSpan data);

    struct RatchetMessage
    {
        MessageHeader header;
        Bytes         ciphertext;
    };

    class DoubleRatchet
    {
        public:
            static Result<DoubleRatchet> init_initiator(
                const crypto::KdfKey&       shared_secret,
                const crypto::X25519Public& their_signed_prekey
            );

            static Result<DoubleRatchet> init_responder(
                const crypto::KdfKey&      shared_secret,
                const crypto::X25519KeyPair& our_signed_prekey
            );

            static Result<DoubleRatchet> from_state(RatchetState state);

            Result<RatchetMessage> encrypt(ByteSpan plaintext);
            Result<Bytes> decrypt(const RatchetMessage& message);

            [[nodiscard]] Channel current_channel() const;

            [[nodiscard]] const RatchetState& state() const noexcept { return state_; }

        private:
            DoubleRatchet() = default;

            Status dh_ratchet_step(const crypto::X25519Public& their_new_dh);
            Result<crypto::KdfKey> skip_message_keys(
                crypto::KdfKey& chain_key, uint32_t& counter,
                uint32_t until, const crypto::X25519Public& dh_pub);

            RatchetState state_;
        };

        [[nodiscard]] Channel derive_channel(const crypto::KdfKey& root_key);
}