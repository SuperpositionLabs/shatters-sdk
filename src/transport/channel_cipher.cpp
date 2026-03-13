#include <shatters/transport/channel_cipher.hpp>

#include <sodium.h>

#include <atomic>
#include <cstring>

namespace shatters
{

struct SodiumChannelCipher::Keys
{
    uint8_t rx[crypto_kx_SESSIONKEYBYTES]{};
    uint8_t tx[crypto_kx_SESSIONKEYBYTES]{};
    
    uint8_t local_pk[crypto_kx_PUBLICKEYBYTES]{};
    uint8_t local_sk[crypto_kx_SECRETKEYBYTES]{};
    
    std::atomic<bool> established{false};

    Keys()
    {
        crypto_kx_keypair(local_pk, local_sk); 
    }

    ~Keys()
    {
        sodium_memzero(local_sk, sizeof(local_sk));
        sodium_memzero(rx, sizeof(rx));
        sodium_memzero(tx, sizeof(tx));
    }

    Keys(const Keys&) = delete;
    Keys& operator=(const Keys&) = delete;
};

SodiumChannelCipher::SodiumChannelCipher() : keys_(std::make_unique<Keys>()) {}

SodiumChannelCipher::~SodiumChannelCipher() = default;

Result<void> SodiumChannelCipher::initialize_as_client(const uint8_t* server_static_pk, size_t pk_len)
{
    if (!server_static_pk || pk_len < crypto_kx_PUBLICKEYBYTES)
        return Error{ErrorCode::InvalidArgument, "invalid server public key"};

    if (crypto_kx_client_session_keys(
            keys_->rx, keys_->tx,
            keys_->local_pk, keys_->local_sk,
            server_static_pk) != 0)
    {
        return Error{ErrorCode::CryptoError, "key exchange failed"};
    }

    keys_->established.store(true, std::memory_order_release);
    return std::monostate{};
}

bool SodiumChannelCipher::is_established() const
{
    return keys_->established.load(std::memory_order_acquire);
}

const uint8_t* SodiumChannelCipher::local_public_key() const
{
    return keys_->local_pk;
}

size_t SodiumChannelCipher::local_public_key_size() const
{
    return crypto_kx_PUBLICKEYBYTES;
}

Result<std::vector<uint8_t>> SodiumChannelCipher::encrypt(const uint8_t* data, size_t len)
{
    if (!keys_->established.load(std::memory_order_acquire))
        return Error{ErrorCode::CryptoError, "channel not established"};

    constexpr size_t NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr size_t TAG_LEN   = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    std::vector<uint8_t> out(NONCE_LEN + len + TAG_LEN);
    randombytes_buf(out.data(), NONCE_LEN);

    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + NONCE_LEN, &ct_len,
        data, len,
        nullptr, 0,
        nullptr,
        out.data(),
        keys_->tx
    );
    out.resize(NONCE_LEN + ct_len);

    return out;
}

Result<std::vector<uint8_t>> SodiumChannelCipher::decrypt(const uint8_t* data, size_t len)
{
    if (!keys_->established.load(std::memory_order_acquire))
        return Error{ErrorCode::CryptoError, "channel not established"};

    constexpr size_t NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    constexpr size_t TAG_LEN   = crypto_aead_xchacha20poly1305_ietf_ABYTES;

    if (len < NONCE_LEN + TAG_LEN)
        return Error{ErrorCode::CryptoError, "ciphertext too short"};

    const size_t ct_len = len - NONCE_LEN;
    std::vector<uint8_t> out(ct_len - TAG_LEN);

    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.data(), &pt_len,
            nullptr,
            data + NONCE_LEN, ct_len,
            nullptr, 0,
            data,
            keys_->rx) != 0)
    {
        return Error{ErrorCode::CryptoError, "decryption failed (auth tag mismatch)"};
    }
    out.resize(pt_len);

    return out;
}

void SodiumChannelCipher::reset()
{
    sodium_memzero(keys_->rx, sizeof(keys_->rx));
    sodium_memzero(keys_->tx, sizeof(keys_->tx));
    keys_->established.store(false, std::memory_order_release);

    crypto_kx_keypair(keys_->local_pk, keys_->local_sk);
}

}
