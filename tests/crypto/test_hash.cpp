#include <gtest/gtest.h>
#include <shatters/init.hpp>
#include <shatters/crypto/hash.hpp>

using namespace shatters::crypto;

class HashTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { shatters::init(); }
};

TEST_F(HashTest, OutputIs32Bytes) {
    const uint8_t data[] = "hello";
    auto hash = blake2b(data, 5);
    EXPECT_EQ(hash.size(), 32u);
}

TEST_F(HashTest, Deterministic) {
    const uint8_t data[] = "shatters";
    auto h1 = blake2b(data, 8);
    auto h2 = blake2b(data, 8);
    EXPECT_EQ(h1, h2);
}

TEST_F(HashTest, DifferentInputDifferentHash) {
    const uint8_t a[] = "alice";
    const uint8_t b[] = "bobxx";
    auto ha = blake2b(a, 5);
    auto hb = blake2b(b, 5);
    EXPECT_NE(ha, hb);
}

TEST_F(HashTest, KeyedHash) {
    const uint8_t data[] = "message";
    const uint8_t key[] = "secret_key_16byt";
    auto h = blake2b_keyed(data, 7, key, 16);
    EXPECT_EQ(h.size(), 32u);
}

TEST_F(HashTest, KeyedVsUnkeyedDiffer) {
    const uint8_t data[] = "same data";
    const uint8_t key[] = "secret_key_16byt";
    auto unkeyed = blake2b(data, 9);
    auto keyed = blake2b_keyed(data, 9, key, 16);
    EXPECT_NE(unkeyed, keyed);
}

TEST_F(HashTest, DifferentKeysDifferentHash) {
    const uint8_t data[] = "same data";
    const uint8_t k1[] = "key_one_16bytess";
    const uint8_t k2[] = "key_two_16bytess";
    auto h1 = blake2b_keyed(data, 9, k1, 16);
    auto h2 = blake2b_keyed(data, 9, k2, 16);
    EXPECT_NE(h1, h2);
}
