#include <gtest/gtest.h>
#include <shatters/init.hpp>
#include <shatters/crypto/kdf.hpp>
#include <shatters/crypto/random.hpp>

#include <cstring>

using namespace shatters::crypto;

class KdfTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { shatters::init(); }
};

TEST_F(KdfTest, DeterministicOutput) {
    const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03};
    const uint8_t ikm[]  = {0x0a, 0x0b, 0x0c, 0x0d};
    const uint8_t info[] = "shattersTest";

    uint8_t out1[32], out2[32];
    hkdf_sha512(out1, 32, salt, 4, ikm, 4, info, 12);
    hkdf_sha512(out2, 32, salt, 4, ikm, 4, info, 12);

    EXPECT_EQ(std::memcmp(out1, out2, 32), 0);
}

TEST_F(KdfTest, DifferentIkmProducesDifferentOutput) {
    const uint8_t salt[] = {0x00};
    const uint8_t ikm1[] = {0x01};
    const uint8_t ikm2[] = {0x02};
    const uint8_t info[] = "test";

    uint8_t out1[32], out2[32];
    hkdf_sha512(out1, 32, salt, 1, ikm1, 1, info, 4);
    hkdf_sha512(out2, 32, salt, 1, ikm2, 1, info, 4);

    EXPECT_NE(std::memcmp(out1, out2, 32), 0);
}

TEST_F(KdfTest, DifferentInfoProducesDifferentOutput) {
    const uint8_t salt[] = {0x00};
    const uint8_t ikm[]  = {0x01};
    const uint8_t info1[] = "alpha";
    const uint8_t info2[] = "bravo";

    uint8_t out1[32], out2[32];
    hkdf_sha512(out1, 32, salt, 1, ikm, 1, info1, 5);
    hkdf_sha512(out2, 32, salt, 1, ikm, 1, info2, 5);

    EXPECT_NE(std::memcmp(out1, out2, 32), 0);
}

TEST_F(KdfTest, DifferentSaltProducesDifferentOutput) {
    const uint8_t salt1[] = {0xAA};
    const uint8_t salt2[] = {0xBB};
    const uint8_t ikm[]   = {0x01};
    const uint8_t info[]  = "test";

    uint8_t out1[32], out2[32];
    hkdf_sha512(out1, 32, salt1, 1, ikm, 1, info, 4);
    hkdf_sha512(out2, 32, salt2, 1, ikm, 1, info, 4);

    EXPECT_NE(std::memcmp(out1, out2, 32), 0);
}

TEST_F(KdfTest, NullSaltWorks) {
    const uint8_t ikm[]  = {0x01, 0x02, 0x03};
    const uint8_t info[] = "shattersX3DH";

    uint8_t out[32];
    EXPECT_NO_THROW(hkdf_sha512(out, 32, nullptr, 0, ikm, 3, info, 12));

    // Output should not be all zeros
    uint8_t zeros[32] = {};
    EXPECT_NE(std::memcmp(out, zeros, 32), 0);
}

TEST_F(KdfTest, OutputLength64) {
    const uint8_t ikm[]  = {0x01};
    const uint8_t info[] = "test";

    uint8_t out[64];
    EXPECT_NO_THROW(hkdf_sha512(out, 64, nullptr, 0, ikm, 1, info, 4));

    uint8_t zeros[64] = {};
    EXPECT_NE(std::memcmp(out, zeros, 64), 0);
}
