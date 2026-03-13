#pragma once

#include <shatters/types.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace shatters
{

class IChannelCipher
{
    public:
        virtual ~IChannelCipher() = default;

        /// Generate ephemeral keypair and derive session keys from servers static public key.
        virtual Result<void> initialize_as_client(const uint8_t* server_static_pk, size_t pk_len) = 0;

        virtual bool is_established() const = 0;

        virtual const uint8_t* local_public_key() const = 0;
        virtual size_t local_public_key_size() const = 0;

        /// Encrypt a plaintext frame.
        virtual Result<std::vector<uint8_t>> encrypt(const uint8_t* data, size_t len) = 0;
        virtual Result<std::vector<uint8_t>> decrypt(const uint8_t* data, size_t len) = 0;

        virtual void reset() = 0;
};

/// IChannelCipher backed by libsodium crypto_kx + XChaCha20-Poly1305.
class SodiumChannelCipher : public IChannelCipher
{
    public:
        SodiumChannelCipher();
        ~SodiumChannelCipher() override;

        Result<void> initialize_as_client(const uint8_t* server_static_pk, size_t pk_len) override;
        bool is_established() const override;
        
        const uint8_t* local_public_key() const override;
        size_t local_public_key_size() const override;
        
        Result<std::vector<uint8_t>> encrypt(const uint8_t* data, size_t len) override;
        Result<std::vector<uint8_t>> decrypt(const uint8_t* data, size_t len) override;

        void reset() override;

        SodiumChannelCipher(const SodiumChannelCipher&) = delete;
        SodiumChannelCipher& operator=(const SodiumChannelCipher&) = delete;

    private:
        struct Keys;
        std::unique_ptr<Keys> keys_;
};

}