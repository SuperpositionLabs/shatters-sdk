#include <shatters/crypto/aead.hpp>
#include <shatters/crypto/kdf.hpp>
#include <shatters/crypto/keys.hpp>

#include <sodium.h>
#include <gtest/gtest.h>

#include <cstring>

namespace crypto = shatters::crypto;

class CryptoTest : public ::testing::Test
{
protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};

TEST_F(CryptoTest, IdentityKeyPairGenerate)
{
    auto result = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(result.is_ok());

    const auto& kp = result.value();
    crypto::PublicKey zero{};
    EXPECT_NE(kp.ed25519_public(), zero);

    crypto::X25519Public x_zero{};
    EXPECT_NE(kp.x25519_public(), x_zero);
}

TEST_F(CryptoTest, IdentityKeyPairFromSeed)
{
    auto gen = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(gen.is_ok());

    auto seed = gen.value().seed();

    auto restored = crypto::IdentityKeyPair::from_seed(seed.span());
    ASSERT_TRUE(restored.is_ok());

    EXPECT_EQ(gen.value().ed25519_public(), restored.value().ed25519_public());
    EXPECT_EQ(gen.value().x25519_public(),  restored.value().x25519_public());
}

TEST_F(CryptoTest, IdentityKeyPairSignVerify)
{
    auto gen = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(gen.is_ok());

    const std::string msg = "hello shatters";
    shatters::ByteSpan msg_span{
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()};

    auto sig = gen.value().sign(msg_span);
    ASSERT_TRUE(sig.is_ok());

    auto verify = crypto::verify_signature(
        msg_span, sig.value(), gen.value().ed25519_public());
    EXPECT_TRUE(verify.is_ok());

    const std::string bad = "hello tampered";
    shatters::ByteSpan bad_span{
        reinterpret_cast<const uint8_t*>(bad.data()), bad.size()};
    auto bad_verify = crypto::verify_signature(
        bad_span, sig.value(), gen.value().ed25519_public());
    EXPECT_TRUE(bad_verify.is_err());
}

TEST_F(CryptoTest, X25519KeyPairGenerate)
{
    auto result = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(result.is_ok());

    crypto::X25519Public zero{};
    EXPECT_NE(result.value().public_key(), zero);
}

TEST_F(CryptoTest, X25519KeyPairFromSecret)
{
    auto gen = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(gen.is_ok());

    auto restored = crypto::X25519KeyPair::from_secret(gen.value().secret_key().span());
    ASSERT_TRUE(restored.is_ok());

    EXPECT_EQ(gen.value().public_key(), restored.value().public_key());
}

TEST_F(CryptoTest, X25519DHSharedSecret)
{
    auto alice = crypto::X25519KeyPair::generate();
    auto bob   = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(alice.is_ok());
    ASSERT_TRUE(bob.is_ok());

    auto shared_ab = crypto::x25519_dh(alice.value().secret_key(), bob.value().public_key());
    auto shared_ba = crypto::x25519_dh(bob.value().secret_key(), alice.value().public_key());
    ASSERT_TRUE(shared_ab.is_ok());
    ASSERT_TRUE(shared_ba.is_ok());

    EXPECT_EQ(shared_ab.value().array(), shared_ba.value().array());
}

TEST_F(CryptoTest, Ed25519ToX25519Conversion)
{
    auto ik = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(ik.is_ok());

    auto converted = crypto::ed25519_pk_to_x25519(ik.value().ed25519_public());
    ASSERT_TRUE(converted.is_ok());

    EXPECT_EQ(converted.value(), ik.value().x25519_public());
}

TEST_F(CryptoTest, AeadEncryptDecrypt)
{
    crypto::AeadKey key{};
    randombytes_buf(key.data(), key.size());

    crypto::AeadNonce nonce = crypto::generate_nonce();

    const std::string plaintext = "secret message for shatters";
    shatters::ByteSpan pt{reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()};

    const std::string ad_str = "associated data";
    shatters::ByteSpan ad{reinterpret_cast<const uint8_t*>(ad_str.data()), ad_str.size()};

    auto ct = crypto::aead_encrypt(pt, ad, nonce, key);
    ASSERT_TRUE(ct.is_ok());
    EXPECT_EQ(ct.value().size(), plaintext.size() + crypto::AEAD_TAG_SIZE);

    auto decrypted = crypto::aead_decrypt(ct.value(), ad, nonce, key);
    ASSERT_TRUE(decrypted.is_ok());
    EXPECT_EQ(decrypted.value().size(), plaintext.size());
    EXPECT_EQ(std::memcmp(decrypted.value().data(), plaintext.data(), plaintext.size()), 0);
}

TEST_F(CryptoTest, AeadDecryptTampered)
{
    crypto::AeadKey key{};
    randombytes_buf(key.data(), key.size());

    crypto::AeadNonce nonce = crypto::generate_nonce();

    const std::string plaintext = "secret";
    shatters::ByteSpan pt{reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()};
    shatters::ByteSpan empty{};

    auto ct = crypto::aead_encrypt(pt, empty, nonce, key);
    ASSERT_TRUE(ct.is_ok());

    auto tampered = ct.value();
    tampered[0] ^= 0xFF;

    auto result = crypto::aead_decrypt(tampered, empty, nonce, key);
    EXPECT_TRUE(result.is_err());
}

TEST_F(CryptoTest, AeadSealOpen)
{
    crypto::AeadKey key{};
    randombytes_buf(key.data(), key.size());

    const std::string plaintext = "sealed message";
    shatters::ByteSpan pt{reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()};
    shatters::ByteSpan empty{};

    auto sealed = crypto::aead_seal(pt, empty, key);
    ASSERT_TRUE(sealed.is_ok());
    EXPECT_EQ(sealed.value().size(),
              crypto::AEAD_NONCE_SIZE + plaintext.size() + crypto::AEAD_TAG_SIZE);

    auto opened = crypto::aead_open(sealed.value(), empty, key);
    ASSERT_TRUE(opened.is_ok());
    EXPECT_EQ(opened.value().size(), plaintext.size());
    EXPECT_EQ(std::memcmp(opened.value().data(), plaintext.data(), plaintext.size()), 0);
}

TEST_F(CryptoTest, AeadNonceFromCounter)
{
    auto n0 = crypto::nonce_from_counter(0);
    auto n1 = crypto::nonce_from_counter(1);
    EXPECT_NE(n0, n1);

    EXPECT_EQ(n1[23], 1);
    EXPECT_EQ(n1[22], 0);
}

TEST_F(CryptoTest, HkdfExtract)
{
    std::array<uint8_t, 32> salt{};
    randombytes_buf(salt.data(), salt.size());

    const std::string ikm_str = "input keying material";
    shatters::ByteSpan ikm{reinterpret_cast<const uint8_t*>(ikm_str.data()), ikm_str.size()};

    auto prk = crypto::hkdf_extract(salt, ikm);
    ASSERT_TRUE(prk.is_ok());

    auto prk2 = crypto::hkdf_extract(salt, ikm);
    ASSERT_TRUE(prk2.is_ok());
    EXPECT_EQ(prk.value(), prk2.value());
}

TEST_F(CryptoTest, HkdfExpandDeterministic)
{
    crypto::KdfKey prk{};
    randombytes_buf(prk.data(), prk.size());

    const std::string info_str = "test info";
    shatters::ByteSpan info{reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()};

    auto okm1 = crypto::hkdf_expand(prk, info, 64);
    auto okm2 = crypto::hkdf_expand(prk, info, 64);
    ASSERT_TRUE(okm1.is_ok());
    ASSERT_TRUE(okm2.is_ok());
    EXPECT_EQ(okm1.value(), okm2.value());
}

TEST_F(CryptoTest, ChainKdfAdvances)
{
    crypto::KdfKey ck{};
    randombytes_buf(ck.data(), ck.size());

    auto step1 = crypto::chain_kdf(ck);
    ASSERT_TRUE(step1.is_ok());

    EXPECT_NE(step1.value().chain_key, ck);
    EXPECT_NE(step1.value().chain_key, step1.value().message_key);

    auto step2 = crypto::chain_kdf(step1.value().chain_key);
    ASSERT_TRUE(step2.is_ok());
    EXPECT_NE(step2.value().chain_key, step1.value().chain_key);
    EXPECT_NE(step2.value().message_key, step1.value().message_key);
}

TEST_F(CryptoTest, RootKdfProducesDifferentKeys)
{
    crypto::KdfKey rk{};
    randombytes_buf(rk.data(), rk.size());

    auto alice = crypto::X25519KeyPair::generate();
    auto bob   = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(alice.is_ok());
    ASSERT_TRUE(bob.is_ok());

    auto dh = crypto::x25519_dh(alice.value().secret_key(), bob.value().public_key());
    ASSERT_TRUE(dh.is_ok());

    auto result = crypto::root_kdf(rk, dh.value().span());
    ASSERT_TRUE(result.is_ok());

    EXPECT_NE(result.value().root_key, rk);
    EXPECT_NE(result.value().root_key, result.value().chain_key);
}

TEST_F(CryptoTest, Argon2idDeriveKey)
{
    auto salt = crypto::generate_salt();
    const std::string password = "test-password-123";

    auto key1 = crypto::derive_key_from_password(password, salt);
    ASSERT_TRUE(key1.is_ok());

    auto key2 = crypto::derive_key_from_password(password, salt);
    ASSERT_TRUE(key2.is_ok());
    EXPECT_EQ(key1.value(), key2.value());

    auto key3 = crypto::derive_key_from_password("other-password", salt);
    ASSERT_TRUE(key3.is_ok());
    EXPECT_NE(key1.value(), key3.value());

    auto salt2 = crypto::generate_salt();
    auto key4 = crypto::derive_key_from_password(password, salt2);
    ASSERT_TRUE(key4.is_ok());
    EXPECT_NE(key1.value(), key4.value());
}