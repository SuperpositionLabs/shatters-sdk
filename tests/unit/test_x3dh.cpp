#include <shatters/x3dh/x3dh.hpp>
#include <shatters/crypto/keys.hpp>
#include <shatters/types.hpp>

#include <sodium.h>
#include <gtest/gtest.h>

#include <cassert>

namespace x3dh   = shatters::x3dh;
namespace crypto = shatters::crypto;

namespace
{

x3dh::PreKeyBundle make_bundle(
    const crypto::IdentityKeyPair&   identity,
    const crypto::X25519KeyPair&     spk,
    std::vector<x3dh::OneTimePreKey> opks = {})
{
    shatters::ByteSpan spk_span{spk.public_key().data(), spk.public_key().size()};
    auto sig = identity.sign(spk_span);
    assert(sig.is_ok());

    x3dh::PreKeyBundle b;
    b.identity_key      = identity.ed25519_public();
    b.signed_prekey     = spk.public_key();
    b.signed_prekey_sig = sig.value();
    b.one_time_prekeys  = std::move(opks);
    return b;
}

} // namespace

class X3DHTest : public ::testing::Test
{
protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};

TEST_F(X3DHTest, FullHandshakeWithOpk)
{
    auto bob_ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(bob_ik.is_ok());
    auto bob_spk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(bob_spk.is_ok());
    auto bob_opk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(bob_opk.is_ok());

    x3dh::OneTimePreKey opk_entry{1, bob_opk.value().public_key()};
    auto bundle = make_bundle(bob_ik.value(), bob_spk.value(), {opk_entry});

    auto alice_ik = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(alice_ik.is_ok());

    auto result = x3dh::initiate(alice_ik.value(), bundle);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().opk_id, 1u);

    auto sk_bob = x3dh::respond(
        bob_ik.value(),
        bob_spk.value(),
        &bob_opk.value(),
        alice_ik.value().ed25519_public(),
        result.value().ephemeral_public);
    ASSERT_TRUE(sk_bob.is_ok());

    EXPECT_EQ(result.value().shared_secret, sk_bob.value());
}

TEST_F(X3DHTest, FullHandshakeWithoutOpk)
{
    auto bob_ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(bob_ik.is_ok());
    auto bob_spk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(bob_spk.is_ok());

    auto bundle = make_bundle(bob_ik.value(), bob_spk.value());

    auto alice_ik = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(alice_ik.is_ok());

    auto result = x3dh::initiate(alice_ik.value(), bundle);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().opk_id, x3dh::NO_OPK);

    auto sk_bob = x3dh::respond(
        bob_ik.value(),
        bob_spk.value(),
        nullptr,
        alice_ik.value().ed25519_public(),
        result.value().ephemeral_public);
    ASSERT_TRUE(sk_bob.is_ok());

    EXPECT_EQ(result.value().shared_secret, sk_bob.value());
}

TEST_F(X3DHTest, DifferentIdentitiesProduceDifferentSecrets)
{
    auto bob_ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(bob_ik.is_ok());
    auto bob_spk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(bob_spk.is_ok());
    auto bundle = make_bundle(bob_ik.value(), bob_spk.value());

    auto alice_ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(alice_ik.is_ok());
    auto alice2_ik = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(alice2_ik.is_ok());

    auto r1 = x3dh::initiate(alice_ik.value(),  bundle);
    auto r2 = x3dh::initiate(alice2_ik.value(), bundle);
    ASSERT_TRUE(r1.is_ok());
    ASSERT_TRUE(r2.is_ok());

    EXPECT_NE(r1.value().shared_secret, r2.value().shared_secret);
}

TEST_F(X3DHTest, InitiateRejectsBadSignature)
{
    auto bob_ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(bob_ik.is_ok());
    auto bob_spk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(bob_spk.is_ok());

    auto bundle = make_bundle(bob_ik.value(), bob_spk.value());
    bundle.signed_prekey_sig[0] ^= 0xFF;

    auto alice_ik = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(alice_ik.is_ok());

    auto result = x3dh::initiate(alice_ik.value(), bundle);
    EXPECT_TRUE(result.is_err());
}

TEST_F(X3DHTest, BundleSerializeDeserializeRoundTrip)
{
    auto ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(ik.is_ok());
    auto spk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(spk.is_ok());
    auto opk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(opk.is_ok());

    x3dh::OneTimePreKey opk_entry{42, opk.value().public_key()};
    auto bundle = make_bundle(ik.value(), spk.value(), {opk_entry});

    auto bytes    = x3dh::serialize_bundle(bundle);
    auto restored = x3dh::deserialize_bundle(bytes);
    ASSERT_TRUE(restored.is_ok());

    EXPECT_EQ(restored.value().identity_key,      bundle.identity_key);
    EXPECT_EQ(restored.value().signed_prekey,     bundle.signed_prekey);
    EXPECT_EQ(restored.value().signed_prekey_sig, bundle.signed_prekey_sig);
    ASSERT_EQ(restored.value().one_time_prekeys.size(), 1u);
    EXPECT_EQ(restored.value().one_time_prekeys[0].id,         42u);
    EXPECT_EQ(restored.value().one_time_prekeys[0].public_key, opk_entry.public_key);
}

TEST_F(X3DHTest, BundleDeserializeTooShort)
{
    shatters::Bytes data(10, 0);
    auto result = x3dh::deserialize_bundle(data);
    EXPECT_TRUE(result.is_err());
}

TEST_F(X3DHTest, BundleDeserializeTruncatedOpks)
{
    auto ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(ik.is_ok());
    auto spk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(spk.is_ok());
    auto opk = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(opk.is_ok());

    x3dh::OneTimePreKey opk_entry{1, opk.value().public_key()};
    auto bundle = make_bundle(ik.value(), spk.value(), {opk_entry});
    auto bytes  = x3dh::serialize_bundle(bundle);

    // Truncate so the OPK payload is cut short
    bytes.resize(bytes.size() - 10);
    auto result = x3dh::deserialize_bundle(bytes);
    EXPECT_TRUE(result.is_err());
}

TEST_F(X3DHTest, InitialMessageSerializeDeserializeRoundTrip)
{
    auto ik  = crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(ik.is_ok());
    auto eph = crypto::X25519KeyPair::generate();
    ASSERT_TRUE(eph.is_ok());

    x3dh::InitialMessage msg;
    msg.sender_identity_key = ik.value().ed25519_public();
    msg.ephemeral_key       = eph.value().public_key();
    msg.opk_id              = 7;
    msg.ciphertext          = {0x01, 0x02, 0x03};

    auto bytes    = x3dh::serialize_initial(msg);
    auto restored = x3dh::deserialize_initial(bytes);
    ASSERT_TRUE(restored.is_ok());

    EXPECT_EQ(restored.value().sender_identity_key, msg.sender_identity_key);
    EXPECT_EQ(restored.value().ephemeral_key,       msg.ephemeral_key);
    EXPECT_EQ(restored.value().opk_id,              7u);
    EXPECT_EQ(restored.value().ciphertext,          msg.ciphertext);
}

TEST_F(X3DHTest, InitialMessageDeserializeTooShort)
{
    shatters::Bytes data(10, 0);
    auto result = x3dh::deserialize_initial(data);
    EXPECT_TRUE(result.is_err());
}
