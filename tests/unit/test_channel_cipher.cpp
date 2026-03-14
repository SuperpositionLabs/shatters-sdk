#include <shatters/transport/channel_cipher.hpp>
#include <shatters/transport/noise.hpp>

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

            // Generate an X25519 keypair for the "server"
            randombytes_buf(server_sk, sizeof(server_sk));
            crypto_scalarmult_base(server_pk, server_sk);
        }

        uint8_t server_pk[32]{};
        uint8_t server_sk[32]{};
};

TEST_F(ChannelCipherTest, StartsUnestablished)
{
    shatters::NoiseChannelCipher cipher;
    EXPECT_FALSE(cipher.is_established());
}

TEST_F(ChannelCipherTest, WriteHandshakeProducesMessage)
{
    shatters::NoiseChannelCipher cipher;
    auto result = cipher.write_handshake(server_pk, sizeof(server_pk));
    ASSERT_TRUE(result.is_ok());

    // NK message 1 = 32 (ephemeral) + 16 (AEAD tag on empty payload) = 48
    EXPECT_EQ(result.value().size(), 48u);
    EXPECT_FALSE(cipher.is_established());
}

TEST_F(ChannelCipherTest, WriteHandshakeRejectsShortKey)
{
    shatters::NoiseChannelCipher cipher;
    uint8_t short_key[4] = {1, 2, 3, 4};
    auto result = cipher.write_handshake(short_key, sizeof(short_key));
    EXPECT_TRUE(result.is_err());
    EXPECT_EQ(result.error().code, shatters::ErrorCode::InvalidArgument);
}

TEST_F(ChannelCipherTest, ReadHandshakeRejectsWithoutWrite)
{
    shatters::NoiseChannelCipher cipher;
    uint8_t dummy[48]{};
    auto result = cipher.read_handshake(dummy, sizeof(dummy));
    EXPECT_TRUE(result.is_err());
}

TEST_F(ChannelCipherTest, ResetAllowsReuse)
{
    shatters::NoiseChannelCipher cipher;
    auto r1 = cipher.write_handshake(server_pk, sizeof(server_pk));
    ASSERT_TRUE(r1.is_ok());

    cipher.reset();

    auto r2 = cipher.write_handshake(server_pk, sizeof(server_pk));
    EXPECT_TRUE(r2.is_ok());
}
}