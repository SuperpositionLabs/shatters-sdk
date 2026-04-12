#include <shatters/ratchet/double_ratchet.hpp>
#include <shatters/crypto/kdf.hpp>
#include <shatters/crypto/keys.hpp>
#include <shatters/types.hpp>

#include <sodium.h>
#include <gtest/gtest.h>

#include <cassert>
#include <string_view>

namespace ratchet = shatters::ratchet;
namespace crypto  = shatters::crypto;

namespace
{

shatters::Bytes make_plaintext(std::string_view str)
{
    return {reinterpret_cast<const uint8_t*>(str.data()),
            reinterpret_cast<const uint8_t*>(str.data()) + str.size()};
}

struct RatchetPair
{
    ratchet::DoubleRatchet initiator;
    ratchet::DoubleRatchet responder;
};

RatchetPair make_pair()
{
    crypto::KdfKey shared_secret{};
    randombytes_buf(shared_secret.data(), shared_secret.size());

    auto spk = crypto::X25519KeyPair::generate();
    assert(spk.is_ok());

    auto init_r = ratchet::DoubleRatchet::init_initiator(shared_secret, spk.value().public_key());
    assert(init_r.is_ok());
    auto resp_r = ratchet::DoubleRatchet::init_responder(shared_secret, spk.value());
    assert(resp_r.is_ok());

    return {std::move(init_r).take_value(), std::move(resp_r).take_value()};
}

} // namespace

class DoubleRatchetTest : public ::testing::Test
{
protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
};

TEST_F(DoubleRatchetTest, BasicEncryptDecrypt)
{
    auto [alice, bob] = make_pair();

    auto pt = make_plaintext("hello shatters");
    auto ct = alice.encrypt(pt);
    ASSERT_TRUE(ct.is_ok());

    auto dt = bob.decrypt(ct.value());
    ASSERT_TRUE(dt.is_ok());
    EXPECT_EQ(dt.value(), pt);
}

TEST_F(DoubleRatchetTest, MultipleMessagesAliceToBob)
{
    auto [alice, bob] = make_pair();

    for (int i = 0; i < 10; ++i)
    {
        auto pt = make_plaintext("message");
        auto ct = alice.encrypt(pt);
        ASSERT_TRUE(ct.is_ok())   << "encrypt failed at " << i;

        auto dt = bob.decrypt(ct.value());
        ASSERT_TRUE(dt.is_ok())   << "decrypt failed at " << i;
        EXPECT_EQ(dt.value(), pt) << "plaintext mismatch at " << i;
    }
}

TEST_F(DoubleRatchetTest, BidirectionalExchange)
{
    auto [alice, bob] = make_pair();

    auto pt_ab = make_plaintext("alice to bob");
    auto ct_ab = alice.encrypt(pt_ab);
    ASSERT_TRUE(ct_ab.is_ok());
    auto dt_ab = bob.decrypt(ct_ab.value());
    ASSERT_TRUE(dt_ab.is_ok());
    EXPECT_EQ(dt_ab.value(), pt_ab);

    auto pt_ba = make_plaintext("bob to alice");
    auto ct_ba = bob.encrypt(pt_ba);
    ASSERT_TRUE(ct_ba.is_ok());
    auto dt_ba = alice.decrypt(ct_ba.value());
    ASSERT_TRUE(dt_ba.is_ok());
    EXPECT_EQ(dt_ba.value(), pt_ba);

    auto pt_ab2 = make_plaintext("alice second");
    auto ct_ab2 = alice.encrypt(pt_ab2);
    ASSERT_TRUE(ct_ab2.is_ok());
    auto dt_ab2 = bob.decrypt(ct_ab2.value());
    ASSERT_TRUE(dt_ab2.is_ok());
    EXPECT_EQ(dt_ab2.value(), pt_ab2);

    auto pt_ba2 = make_plaintext("bob second");
    auto ct_ba2 = bob.encrypt(pt_ba2);
    ASSERT_TRUE(ct_ba2.is_ok());
    auto dt_ba2 = alice.decrypt(ct_ba2.value());
    ASSERT_TRUE(dt_ba2.is_ok());
    EXPECT_EQ(dt_ba2.value(), pt_ba2);
}

TEST_F(DoubleRatchetTest, OutOfOrderDecryption)
{
    auto [alice, bob] = make_pair();

    auto pt0 = make_plaintext("msg0");
    auto pt1 = make_plaintext("msg1");
    auto pt2 = make_plaintext("msg2");

    auto ct0 = alice.encrypt(pt0);
    ASSERT_TRUE(ct0.is_ok());
    auto ct1 = alice.encrypt(pt1);
    ASSERT_TRUE(ct1.is_ok());
    auto ct2 = alice.encrypt(pt2);
    ASSERT_TRUE(ct2.is_ok());

    // Decrypt out-of-order: 2 first, then 0 and 1 via skipped keys
    auto dt2 = bob.decrypt(ct2.value());
    ASSERT_TRUE(dt2.is_ok());
    EXPECT_EQ(dt2.value(), pt2);

    auto dt0 = bob.decrypt(ct0.value());
    ASSERT_TRUE(dt0.is_ok());
    EXPECT_EQ(dt0.value(), pt0);

    auto dt1 = bob.decrypt(ct1.value());
    ASSERT_TRUE(dt1.is_ok());
    EXPECT_EQ(dt1.value(), pt1);
}

TEST_F(DoubleRatchetTest, MaxSkipEnforced)
{
    auto [alice, bob] = make_pair();

    // Encrypt MAX_SKIP+2 messages; deliver only the last one.
    // Bob must skip MAX_SKIP+1 keys which exceeds the limit.
    for (size_t i = 0; i <= ratchet::MAX_SKIP; ++i)
    {
        auto ct = alice.encrypt(make_plaintext("skip"));
        ASSERT_TRUE(ct.is_ok()) << "encrypt failed at " << i;
    }

    auto overflow_ct = alice.encrypt(make_plaintext("overflow"));
    ASSERT_TRUE(overflow_ct.is_ok());

    auto result = bob.decrypt(overflow_ct.value());
    EXPECT_TRUE(result.is_err());
}

TEST_F(DoubleRatchetTest, TamperedCiphertextFails)
{
    auto [alice, bob] = make_pair();

    auto ct = alice.encrypt(make_plaintext("tamper test"));
    ASSERT_TRUE(ct.is_ok());

    auto tampered = ct.value();
    tampered.ciphertext[0] ^= 0xFF;

    auto result = bob.decrypt(tampered);
    EXPECT_TRUE(result.is_err());
}

TEST_F(DoubleRatchetTest, StateSerializeDeserializeRoundTrip)
{
    auto [alice, bob] = make_pair();

    for (int i = 0; i < 3; ++i)
    {
        auto ct = alice.encrypt(make_plaintext("advance"));
        ASSERT_TRUE(ct.is_ok());
        auto dt = bob.decrypt(ct.value());
        ASSERT_TRUE(dt.is_ok());
    }

    auto state_bytes   = ratchet::serialize_state(bob.state());
    auto restored      = ratchet::deserialize_state(state_bytes);
    ASSERT_TRUE(restored.is_ok());

    auto bob2 = ratchet::DoubleRatchet::from_state(std::move(restored).take_value());
    ASSERT_TRUE(bob2.is_ok());

    auto pt = make_plaintext("after restore");
    auto ct = alice.encrypt(pt);
    ASSERT_TRUE(ct.is_ok());

    auto dt = bob2.value().decrypt(ct.value());
    ASSERT_TRUE(dt.is_ok());
    EXPECT_EQ(dt.value(), pt);
}

TEST_F(DoubleRatchetTest, StateDeserializeTooShort)
{
    shatters::Bytes data(10, 0);
    auto result = ratchet::deserialize_state(data);
    EXPECT_TRUE(result.is_err());
}

TEST_F(DoubleRatchetTest, HeaderSerializeDeserializeRoundTrip)
{
    ratchet::MessageHeader h;
    h.dh_public.fill(0xAB);
    h.message_number        = 42;
    h.previous_chain_length = 7;

    auto bytes    = ratchet::serialize_header(h);
    auto restored = ratchet::deserialize_header(bytes);
    ASSERT_TRUE(restored.is_ok());

    EXPECT_EQ(restored.value().dh_public,            h.dh_public);
    EXPECT_EQ(restored.value().message_number,        42u);
    EXPECT_EQ(restored.value().previous_chain_length, 7u);
}

TEST_F(DoubleRatchetTest, HeaderDeserializeTooShort)
{
    shatters::Bytes data(10, 0);
    auto result = ratchet::deserialize_header(data);
    EXPECT_TRUE(result.is_err());
}
