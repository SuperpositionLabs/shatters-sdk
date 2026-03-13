#include <gtest/gtest.h>
#include <shatters/init.hpp>
#include <shatters/constants.hpp>

TEST(SmokeTest, SodiumInitializes) {
    ASSERT_TRUE(shatters::init());
}

TEST(SmokeTest, ConstantsValid) {
    EXPECT_EQ(shatters::kKeySize, 32u);
    EXPECT_EQ(shatters::kSignatureSize, 64u);
    EXPECT_EQ(shatters::kAeadNonceSize, 24u);
    EXPECT_EQ(shatters::kAeadTagSize, 16u);
    EXPECT_EQ(shatters::kHashSize, 32u);
    EXPECT_EQ(shatters::kDeadDropIdSize, 32u);
    EXPECT_EQ(shatters::kDeviceIdSize, 32u);
    EXPECT_EQ(shatters::kFingerprintSize, 20u);
    EXPECT_EQ(shatters::kMaxBlobSize, 32768u);
    EXPECT_EQ(shatters::kMaxGroupSize, 20u);
    EXPECT_EQ(shatters::kPreKeyBatchSize, 100u);
    EXPECT_EQ(shatters::kMaxSkippedKeys, 1000u);
    EXPECT_EQ(shatters::kProtocolVersion, 0x01);
}
