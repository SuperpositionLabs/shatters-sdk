#include <gtest/gtest.h>
#include <shatters/init.hpp>
#include <shatters/crypto/keys.hpp>
#include <shatters/crypto/random.hpp>

#include <string>

using namespace shatters::crypto;

class KeysTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { shatters::init(); }
};

TEST_F(KeysTest, GenerateSigningKeypair) {
    auto kp = generate_signing_keypair();
    EXPECT_NE(kp.public_key, PublicKey{});
}

TEST_F(KeysTest, SignAndVerify) {
    auto kp = generate_signing_keypair();
    const std::string msg = "shatters test message";

    auto sig = sign(kp.secret_key,
                    reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    EXPECT_TRUE(verify(kp.public_key,
                       reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                       sig));
}

TEST_F(KeysTest, VerifyFailsWithWrongMessage) {
    auto kp = generate_signing_keypair();
    const std::string msg = "original";
    const std::string bad = "tampered";

    auto sig = sign(kp.secret_key,
                    reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    EXPECT_FALSE(verify(kp.public_key,
                        reinterpret_cast<const uint8_t*>(bad.data()), bad.size(),
                        sig));
}

TEST_F(KeysTest, VerifyFailsWithWrongKey) {
    auto kp1 = generate_signing_keypair();
    auto kp2 = generate_signing_keypair();
    const std::string msg = "hello";

    auto sig = sign(kp1.secret_key,
                    reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

    EXPECT_FALSE(verify(kp2.public_key,
                        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                        sig));
}

TEST_F(KeysTest, GenerateDHKeypair) {
    auto kp = generate_dh_keypair();
    EXPECT_NE(kp.public_key, PublicKey{});
}

TEST_F(KeysTest, DHSharedSecretIsSymmetric) {
    auto alice = generate_dh_keypair();
    auto bob = generate_dh_keypair();

    auto secret_ab = dh(alice.secret_key, bob.public_key);
    auto secret_ba = dh(bob.secret_key, alice.public_key);

    EXPECT_EQ(secret_ab, secret_ba);
}

TEST_F(KeysTest, DHDifferentPeersProduceDifferentSecrets) {
    auto alice = generate_dh_keypair();
    auto bob = generate_dh_keypair();
    auto carol = generate_dh_keypair();

    auto secret_ab = dh(alice.secret_key, bob.public_key);
    auto secret_ac = dh(alice.secret_key, carol.public_key);

    EXPECT_NE(secret_ab, secret_ac);
}

TEST_F(KeysTest, Ed25519ToX25519Conversion) {
    auto ed_kp = generate_signing_keypair();

    auto x_pk = ed25519_pk_to_x25519(ed_kp.public_key);
    auto x_sk = ed25519_sk_to_x25519(ed_kp.secret_key);

    EXPECT_NE(x_pk, PublicKey{});

    // Verify DH works with converted keys
    auto bob = generate_dh_keypair();
    auto secret1 = dh(x_sk, bob.public_key);
    auto secret2 = dh(bob.secret_key, x_pk);
    EXPECT_EQ(secret1, secret2);
}
