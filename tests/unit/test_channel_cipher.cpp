#include <shatters/transport/channel_cipher.hpp>

#include <sodium.h>
#include <gtest/gtest.h>

namespace
{

class ChannelCipherTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            ASSERT_GE(sodium_init(), -1);
            crypto_kx_keypair(server_pk, server_sk);
        }

        uint8_t server_pk[crypto_kx_PUBLICKEYBYTES]{};
        uint8_t server_sk[crypto_kx_SECRETKEYBYTES]{};
};

TEST_F(ChannelCipherTest, StartsUnestablished)
{
    shatters::SodiumChannelCipher cipher;

    EXPECT_FALSE(cipher.is_established());
    EXPECT_NE(cipher.local_public_key(), nullptr);
    EXPECT_EQ(cipher.local_public_key_size(), crypto_kx_PUBLICKEYBYTES);
}

TEST_F(ChannelCipherTest, InitializeWithValidKey)
{
    shatters::SodiumChannelCipher cipher;

    auto result = cipher.initialize_as_client(server_pk, sizeof(server_pk));

    EXPECT_TRUE(result.is_ok());
    EXPECT_TRUE(cipher.is_established());
}

TEST_F(ChannelCipherTest, InitializeWithShortKey)
{
    shatters::SodiumChannelCipher cipher;
    uint8_t short_key[4] = {1, 2, 3, 4};

    auto result = cipher.initialize_as_client(short_key, sizeof(short_key));

    EXPECT_TRUE(result.is_err());
    EXPECT_EQ(result.error().code, shatters::ErrorCode::InvalidArgument);
}

TEST_F(ChannelCipherTest, EncryptDecryptRoundTrip)
{
    shatters::SodiumChannelCipher client;
    ASSERT_TRUE(client.initialize_as_client(server_pk, sizeof(server_pk)).is_ok());

    uint8_t srv_rx[crypto_kx_SESSIONKEYBYTES], srv_tx[crypto_kx_SESSIONKEYBYTES];
    ASSERT_EQ(crypto_kx_server_session_keys(
        srv_rx, srv_tx,
        server_pk, server_sk,
        client.local_public_key()), 0
    );

    const std::string plaintext = "shatters test payload";
    auto enc = client.encrypt(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    ASSERT_TRUE(enc.is_ok());
    auto& ciphertext = enc.value();
    EXPECT_GT(ciphertext.size(), plaintext.size());

    const size_t ct_body_len = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    
    std::vector<uint8_t> recovered(ct_body_len);
    unsigned long long recovered_len = 0;

    ASSERT_EQ(crypto_aead_xchacha20poly1305_ietf_decrypt(
        recovered.data(), &recovered_len, nullptr,
        ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, ct_body_len,
        nullptr, 0,
        ciphertext.data(),
        srv_rx), 0
    );

    recovered.resize(recovered_len);
    EXPECT_EQ(std::string(recovered.begin(), recovered.end()), plaintext);
}

TEST_F(ChannelCipherTest, ReInitializeAfterReset)
{
    shatters::SodiumChannelCipher cipher;
    ASSERT_TRUE(cipher.initialize_as_client(server_pk, sizeof(server_pk)).is_ok());

    cipher.reset();

    auto result = cipher.initialize_as_client(server_pk, sizeof(server_pk));
    EXPECT_TRUE(result.is_ok());
    EXPECT_TRUE(cipher.is_established());
}
}