#include <shatters/ratchet/double_ratchet.hpp>

#include <sodium.h>

#include <cstring>

namespace shatters::ratchet
{

namespace
{
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
}

Bytes serialize_header(const MessageHeader& header)
{
    Bytes out(RATCHET_HEADER_SIZE);
    size_t pos = 0;

    std::memcpy(out.data() + pos, header.dh_public.data(), 32); pos += 32;
    write_u32_be(out.data() + pos, header.message_number);      pos += 4;
    write_u32_be(out.data() + pos, header.previous_chain_length);

    return out;
}

Result<MessageHeader> deserialize_header(ByteSpan data)
{
    if (data.size() < RATCHET_HEADER_SIZE)
        return Error{ErrorCode::ProtocolError, "ratchet header too short"};

    MessageHeader h{};
    size_t pos = 0;

    std::memcpy(h.dh_public.data(), data.data() + pos, 32); pos += 32;
    h.message_number        = read_u32_be(data.data() + pos); pos += 4;
    h.previous_chain_length = read_u32_be(data.data() + pos);

    return h;
}

constexpr size_t STATE_FIXED_SIZE = 32 * 6 + 4 * 4;
constexpr size_t SKIPPED_ENTRY_SIZE = 32 + 4 + 32;

Bytes serialize_state(const RatchetState& state)
{
    const auto n = static_cast<uint32_t>(state.skipped_keys.size());
    Bytes out(STATE_FIXED_SIZE + n * SKIPPED_ENTRY_SIZE);
    size_t pos = 0;

    std::memcpy(out.data() + pos, state.root_key.data(), 32);        pos += 32;
    std::memcpy(out.data() + pos, state.dh_self_public.data(), 32);  pos += 32;
    std::memcpy(out.data() + pos, state.dh_self_secret.data(), 32);  pos += 32;
    std::memcpy(out.data() + pos, state.dh_remote_public.data(), 32);pos += 32;
    std::memcpy(out.data() + pos, state.send_chain_key.data(), 32);  pos += 32;
    std::memcpy(out.data() + pos, state.recv_chain_key.data(), 32);  pos += 32;
    write_u32_be(out.data() + pos, state.send_count);                pos += 4;
    write_u32_be(out.data() + pos, state.recv_count);                pos += 4;
    write_u32_be(out.data() + pos, state.prev_send_count);           pos += 4;
    write_u32_be(out.data() + pos, n);                               pos += 4;

    for (const auto& [idx, key] : state.skipped_keys)
    {
        std::memcpy(out.data() + pos, idx.dh_public.data(), 32);    pos += 32;
        write_u32_be(out.data() + pos, idx.message_number);         pos += 4;
        std::memcpy(out.data() + pos, key.data(), 32);              pos += 32;
    }

    return out;
}

Result<RatchetState> deserialize_state(ByteSpan data)
{
    if (data.size() < STATE_FIXED_SIZE)
        return Error{ErrorCode::ProtocolError, "ratchet state too short"};

    RatchetState state{};
    size_t pos = 0;

    std::memcpy(state.root_key.data(), data.data() + pos, 32);        pos += 32;
    std::memcpy(state.dh_self_public.data(), data.data() + pos, 32);  pos += 32;
    std::memcpy(state.dh_self_secret.data(), data.data() + pos, 32);  pos += 32;
    std::memcpy(state.dh_remote_public.data(), data.data() + pos, 32);pos += 32;
    std::memcpy(state.send_chain_key.data(), data.data() + pos, 32);  pos += 32;
    std::memcpy(state.recv_chain_key.data(), data.data() + pos, 32);  pos += 32;
    state.send_count      = read_u32_be(data.data() + pos);           pos += 4;
    state.recv_count      = read_u32_be(data.data() + pos);           pos += 4;
    state.prev_send_count = read_u32_be(data.data() + pos);           pos += 4;
    uint32_t n            = read_u32_be(data.data() + pos);           pos += 4;

    if (data.size() < STATE_FIXED_SIZE + n * SKIPPED_ENTRY_SIZE)
        return Error{ErrorCode::ProtocolError, "ratchet state truncated"};

    for (uint32_t i = 0; i < n; ++i)
    {
        SkippedKeyIndex idx{};
        crypto::KdfKey key{};
        std::memcpy(idx.dh_public.data(), data.data() + pos, 32);   pos += 32;
        idx.message_number = read_u32_be(data.data() + pos);        pos += 4;
        std::memcpy(key.data(), data.data() + pos, 32);             pos += 32;
        state.skipped_keys[idx] = key;
    }

    return state;
}

Channel derive_channel(const crypto::KdfKey& root_key)
{
    static constexpr std::string_view label = "shatters-deaddrop";

    unsigned char hash[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, root_key.data(), root_key.size());
    crypto_auth_hmacsha256_update(&st,
        reinterpret_cast<const unsigned char*>(label.data()), label.size());
    crypto_auth_hmacsha256_final(&st, hash);

    Channel ch{};
    std::memcpy(ch.data(), hash, CHANNEL_SIZE);
    return ch;
}

Result<DoubleRatchet> DoubleRatchet::init_initiator(
    const crypto::KdfKey&       shared_secret,
    const crypto::X25519Public& their_signed_prekey)
{
    DoubleRatchet dr;
    auto& s = dr.state_;

    auto dh = crypto::X25519KeyPair::generate();
    SHATTERS_TRY(dh);

    s.dh_self_public = dh.value().public_key();
    std::memcpy(s.dh_self_secret.data(),
                dh.value().secret_key().data(),
                crypto::X25519_KEY_SIZE);

    s.dh_remote_public = their_signed_prekey;

    auto dh_out = crypto::x25519_dh(dh.value().secret_key(), their_signed_prekey);
    SHATTERS_TRY(dh_out);

    auto rk = crypto::root_kdf(shared_secret, dh_out.value().span());
    SHATTERS_TRY(rk);

    s.root_key       = rk.value().root_key;
    s.send_chain_key = rk.value().chain_key;

    return dr;
}

Result<DoubleRatchet> DoubleRatchet::init_responder(
    const crypto::KdfKey&        shared_secret,
    const crypto::X25519KeyPair& our_signed_prekey)
{
    DoubleRatchet dr;
    auto& s = dr.state_;

    s.root_key       = shared_secret;
    s.dh_self_public = our_signed_prekey.public_key();
    std::memcpy(s.dh_self_secret.data(),
                our_signed_prekey.secret_key().data(),
                crypto::X25519_KEY_SIZE);

    return dr;
}

Result<DoubleRatchet> DoubleRatchet::from_state(RatchetState state)
{
    DoubleRatchet dr;
    dr.state_ = std::move(state);
    return dr;
}

Result<RatchetMessage> DoubleRatchet::encrypt(ByteSpan plaintext)
{
    if (state_.send_count == COUNTER_MAX)
        return Error{ErrorCode::BufferOverflow, "send counter exhausted, ratchet step required"};

    auto ck_pair = crypto::chain_kdf(state_.send_chain_key);
    SHATTERS_TRY(ck_pair);

    state_.send_chain_key = ck_pair.value().chain_key;
    const auto& mk = ck_pair.value().message_key;

    MessageHeader header{};
    header.dh_public             = state_.dh_self_public;
    header.message_number        = state_.send_count;
    header.previous_chain_length = state_.prev_send_count;

    auto header_bytes = serialize_header(header);

    crypto::AeadKey aead_key{};
    std::memcpy(aead_key.data(), mk.data(), 32);

    auto nonce_prefix = crypto::derive_nonce_prefix(mk);
    SHATTERS_TRY(nonce_prefix);
    auto nonce = crypto::nonce_from_prefix_counter(
        {nonce_prefix.value().data(), nonce_prefix.value().size()},
        state_.send_count);

    auto ct = crypto::aead_encrypt(plaintext, header_bytes, nonce, aead_key);
    SHATTERS_TRY(ct);

    state_.send_count++;

    return RatchetMessage{
        .header     = header,
        .ciphertext = std::move(ct).take_value(),
    };
}

Result<Bytes> DoubleRatchet::decrypt(const RatchetMessage& message)
{
    const auto& h = message.header;

    SkippedKeyIndex idx{h.dh_public, h.message_number};
    auto it = state_.skipped_keys.find(idx);
    if (it != state_.skipped_keys.end())
    {
        auto mk = it->second;
        state_.skipped_keys.erase(it);

        crypto::AeadKey aead_key{};
        std::memcpy(aead_key.data(), mk.data(), 32);
        auto nonce_prefix = crypto::derive_nonce_prefix(mk);
        if (nonce_prefix.is_err())
            return nonce_prefix.error();
        auto nonce = crypto::nonce_from_prefix_counter(
            {nonce_prefix.value().data(), nonce_prefix.value().size()},
            h.message_number);
        auto header_bytes = serialize_header(h);

        return crypto::aead_decrypt(message.ciphertext, header_bytes, nonce, aead_key);
    }

    if (h.dh_public != state_.dh_remote_public)
    {
        auto skip_r = skip_message_keys(
            state_.recv_chain_key, state_.recv_count,
            h.previous_chain_length,
            state_.dh_remote_public
        );
        SHATTERS_TRY(skip_r);

        SHATTERS_TRY(dh_ratchet_step(h.dh_public));
    }

    auto skip_r2 = skip_message_keys(
        state_.recv_chain_key, state_.recv_count,
        h.message_number,
        h.dh_public
    );
    SHATTERS_TRY(skip_r2);

    auto ck_pair = crypto::chain_kdf(state_.recv_chain_key);
    SHATTERS_TRY(ck_pair);

    state_.recv_chain_key = ck_pair.value().chain_key;
    const auto& mk = ck_pair.value().message_key;
    state_.recv_count++;

    crypto::AeadKey aead_key{};
    std::memcpy(aead_key.data(), mk.data(), 32);
    auto nonce_prefix = crypto::derive_nonce_prefix(mk);
    SHATTERS_TRY(nonce_prefix);
    auto nonce = crypto::nonce_from_prefix_counter(
        {nonce_prefix.value().data(), nonce_prefix.value().size()},
        h.message_number);
    auto header_bytes = serialize_header(h);

    return crypto::aead_decrypt(message.ciphertext, header_bytes, nonce, aead_key);
}

Channel DoubleRatchet::current_channel() const
{
    return derive_channel(state_.root_key);
}

Status DoubleRatchet::dh_ratchet_step(const crypto::X25519Public& their_new_dh)
{
    state_.prev_send_count = state_.send_count;
    state_.send_count = 0;
    state_.recv_count = 0;
    state_.dh_remote_public = their_new_dh;

    auto dh_recv = crypto::x25519_dh(state_.dh_self_secret, their_new_dh);
    SHATTERS_TRY(dh_recv);

    auto rk_recv = crypto::root_kdf(state_.root_key, dh_recv.value().span());
    SHATTERS_TRY(rk_recv);

    state_.root_key       = rk_recv.value().root_key;
    state_.recv_chain_key = rk_recv.value().chain_key;

    auto new_dh = crypto::X25519KeyPair::generate();
    SHATTERS_TRY(new_dh);

    state_.dh_self_public = new_dh.value().public_key();
    std::memcpy(state_.dh_self_secret.data(),
                new_dh.value().secret_key().data(),
                crypto::X25519_KEY_SIZE);

    auto dh_send = crypto::x25519_dh(new_dh.value().secret_key(), their_new_dh);
    SHATTERS_TRY(dh_send);

    auto rk_send = crypto::root_kdf(state_.root_key, dh_send.value().span());
    SHATTERS_TRY(rk_send);

    state_.root_key       = rk_send.value().root_key;
    state_.send_chain_key = rk_send.value().chain_key;

    return {};
}

Result<crypto::KdfKey> DoubleRatchet::skip_message_keys(
    crypto::KdfKey& chain_key, uint32_t& counter,
    uint32_t until, const crypto::X25519Public& dh_pub)
{
    if (until < counter)
        return Error{ErrorCode::CryptoError, "cannot skip backwards"};

    if (until - counter > MAX_SKIP)
        return Error{ErrorCode::CryptoError, "too many skipped messages"};

    crypto::KdfKey last_mk{};
    while (counter < until)
    {
        auto ck_pair = crypto::chain_kdf(chain_key);
        SHATTERS_TRY(ck_pair);

        chain_key = ck_pair.value().chain_key;
        last_mk   = ck_pair.value().message_key;

        SkippedKeyIndex idx{dh_pub, counter};
        state_.skipped_keys[idx] = last_mk;
        counter++;
    }

    while (state_.skipped_keys.size() > MAX_SKIP * 2)
    {
        state_.skipped_keys.erase(state_.skipped_keys.begin());
    }

    return last_mk;
}

}