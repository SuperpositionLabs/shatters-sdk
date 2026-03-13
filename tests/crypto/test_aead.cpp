#include <gtest/gtest.h>
#include <shatters/init.hpp>
#include <shatters/crypto/aead.hpp>
#include <shatters/crypto/random.hpp>

#include <string>

using namespace shatters::crypto;

class AeadTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { shatters::init(); }

    SecureArray<shatters::kKeySize> key = random_secure_array<shatters::kKeySize>();
    AeadNonce nonce = random_byte_array<shatters::kAeadNonceSize>();
};

TEST_F(AeadTest, EncryptDecryptRoundTrip) {
    const std::string msg = "hello shatters";
    auto ct = aead_encrypt(key, nonce,
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    EXPECT_EQ(ct.size(), msg.size() + shatters::kAeadTagSize);

    auto pt = aead_decrypt(key, nonce, ct.data(), ct.size());
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(std::string(pt->begin(), pt->end()), msg);
}

TEST_F(AeadTest, EncryptDecryptWithAAD) {
    const std::string msg = "secret payload";
    const std::string aad = "authenticated header";

    auto ct = aead_encrypt(key, nonce,
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                           reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    auto pt = aead_decrypt(key, nonce, ct.data(), ct.size(),
                           reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(std::string(pt->begin(), pt->end()), msg);
}

TEST_F(AeadTest, DecryptFailsWithWrongKey) {
    const std::string msg = "data";
    auto ct = aead_encrypt(key, nonce,
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    auto wrong_key = random_secure_array<shatters::kKeySize>();
    auto pt = aead_decrypt(wrong_key, nonce, ct.data(), ct.size());
    EXPECT_FALSE(pt.has_value());
}

TEST_F(AeadTest, DecryptFailsWithWrongNonce) {
    const std::string msg = "data";
    auto ct = aead_encrypt(key, nonce,
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    auto wrong_nonce = random_byte_array<shatters::kAeadNonceSize>();
    auto pt = aead_decrypt(key, wrong_nonce, ct.data(), ct.size());
    EXPECT_FALSE(pt.has_value());
}

TEST_F(AeadTest, DecryptFailsWithTamperedCiphertext) {
    const std::string msg = "data";
    auto ct = aead_encrypt(key, nonce,
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    ct[0] ^= 0xFF;
    auto pt = aead_decrypt(key, nonce, ct.data(), ct.size());
    EXPECT_FALSE(pt.has_value());
}

TEST_F(AeadTest, DecryptFailsWithWrongAAD) {
    const std::string msg = "data";
    const std::string aad = "correct";
    const std::string bad_aad = "wrong!!";

    auto ct = aead_encrypt(key, nonce,
                           reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                           reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    auto pt = aead_decrypt(key, nonce, ct.data(), ct.size(),
                           reinterpret_cast<const uint8_t*>(bad_aad.data()), bad_aad.size());
    EXPECT_FALSE(pt.has_value());
}

// --- Padding ---

TEST_F(AeadTest, PadUnpadRoundTrip) {
    const std::string data = "some message content";
    auto padded = pad(reinterpret_cast<const uint8_t*>(data.data()), data.size());

    EXPECT_EQ(padded.size(), shatters::kMaxBlobSize);

    auto result = unpad(padded.data(), padded.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(std::string(result->begin(), result->end()), data);
}

TEST_F(AeadTest, PadOutputHasCorrectSize) {
    const uint8_t data[] = {0x01, 0x02, 0x03};
    auto padded = pad(data, 3, 256);
    EXPECT_EQ(padded.size(), 256u);
}

TEST_F(AeadTest, PadStoresLengthBigEndian) {
    const uint8_t data[] = {0xAA, 0xBB};
    auto padded = pad(data, 2, 64);

    uint32_t stored_len = (static_cast<uint32_t>(padded[0]) << 24) |
                          (static_cast<uint32_t>(padded[1]) << 16) |
                          (static_cast<uint32_t>(padded[2]) << 8) |
                           static_cast<uint32_t>(padded[3]);
    EXPECT_EQ(stored_len, 2u);
    EXPECT_EQ(padded[4], 0xAA);
    EXPECT_EQ(padded[5], 0xBB);
}

TEST_F(AeadTest, PadThrowsIfDataTooLarge) {
    std::vector<uint8_t> big(shatters::kMaxBlobSize, 0);
    EXPECT_THROW(pad(big.data(), big.size()), std::invalid_argument);
}

TEST_F(AeadTest, UnpadFailsOnTruncated) {
    const uint8_t tiny[] = {0x00, 0x01};
    auto result = unpad(tiny, 2);
    EXPECT_FALSE(result.has_value());
}

TEST_F(AeadTest, UnpadFailsOnCorruptLength) {
    // Length header says 999 bytes, but buffer is only 16 bytes total
    uint8_t buf[16] = {};
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x03; buf[3] = 0xE7; // 999
    auto result = unpad(buf, 16);
    EXPECT_FALSE(result.has_value());
}
