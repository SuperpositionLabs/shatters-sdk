#include <gtest/gtest.h>
#include <shatters/init.hpp>
#include <shatters/crypto/secure_memory.hpp>

#include <type_traits>

using namespace shatters::crypto;

class SecureMemoryTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        shatters::init();
    }
};

// --- SecureArray ---

TEST_F(SecureMemoryTest, SecureArrayDefaultZeroInitialized) {
    SecureArray<32> arr;
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(arr[i], 0);
    }
}

TEST_F(SecureMemoryTest, SecureArraySize) {
    EXPECT_EQ(SecureArray<32>::size(), 32u);
    EXPECT_EQ(SecureArray<64>::size(), 64u);
}

TEST_F(SecureMemoryTest, SecureArrayReadWrite) {
    SecureArray<32> arr;
    arr[0] = 0xAB;
    arr[31] = 0xCD;
    EXPECT_EQ(arr[0], 0xAB);
    EXPECT_EQ(arr[31], 0xCD);
}

TEST_F(SecureMemoryTest, SecureArrayMoveConstructor) {
    SecureArray<32> a;
    a[0] = 0x42;
    a[15] = 0xFF;

    SecureArray<32> b(std::move(a));
    EXPECT_EQ(b[0], 0x42);
    EXPECT_EQ(b[15], 0xFF);
    EXPECT_EQ(a[0], 0x00);
    EXPECT_EQ(a[15], 0x00);
}

TEST_F(SecureMemoryTest, SecureArrayMoveAssignment) {
    SecureArray<32> a, b;
    a[0] = 0x11;
    b[0] = 0x22;

    b = std::move(a);
    EXPECT_EQ(b[0], 0x11);
    EXPECT_EQ(a[0], 0x00);
}

TEST_F(SecureMemoryTest, SecureArrayConstantTimeEquality) {
    SecureArray<32> a, b;
    a[0] = 0x42;
    b[0] = 0x42;
    EXPECT_EQ(a, b);

    b[0] = 0x43;
    EXPECT_NE(a, b);
}

TEST_F(SecureMemoryTest, SecureArrayIteration) {
    SecureArray<4> arr;
    arr[0] = 1; arr[1] = 2; arr[2] = 3; arr[3] = 4;

    uint8_t sum = 0;
    for (auto byte : arr) {
        sum += byte;
    }
    EXPECT_EQ(sum, 10);
}

TEST_F(SecureMemoryTest, SecureArrayIsNotCopyable) {
    static_assert(!std::is_copy_constructible_v<SecureArray<32>>);
    static_assert(!std::is_copy_assignable_v<SecureArray<32>>);
}

TEST_F(SecureMemoryTest, SecureArrayIsMoveOnly) {
    static_assert(std::is_move_constructible_v<SecureArray<32>>);
    static_assert(std::is_move_assignable_v<SecureArray<32>>);
}

// --- SecureBuffer ---

TEST_F(SecureMemoryTest, SecureBufferAllocates) {
    SecureBuffer buf(64);
    EXPECT_NE(buf.data(), nullptr);
    EXPECT_EQ(buf.size(), 64u);
    EXPECT_FALSE(buf.empty());
}

TEST_F(SecureMemoryTest, SecureBufferDefaultEmpty) {
    SecureBuffer buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.data(), nullptr);
    EXPECT_EQ(buf.size(), 0u);
}

TEST_F(SecureMemoryTest, SecureBufferReadWrite) {
    SecureBuffer buf(32);
    buf[0] = 0xAB;
    buf[31] = 0xCD;
    EXPECT_EQ(buf[0], 0xAB);
    EXPECT_EQ(buf[31], 0xCD);
}

TEST_F(SecureMemoryTest, SecureBufferMoveConstructor) {
    SecureBuffer a(32);
    a[0] = 0x42;
    auto* original_ptr = a.data();

    SecureBuffer b(std::move(a));
    EXPECT_EQ(b.data(), original_ptr);
    EXPECT_EQ(b[0], 0x42);
    EXPECT_EQ(b.size(), 32u);
    EXPECT_EQ(a.data(), nullptr);
    EXPECT_EQ(a.size(), 0u);
    EXPECT_TRUE(a.empty());
}

TEST_F(SecureMemoryTest, SecureBufferMoveAssignment) {
    SecureBuffer a(32), b(64);
    a[0] = 0x11;

    b = std::move(a);
    EXPECT_EQ(b[0], 0x11);
    EXPECT_EQ(b.size(), 32u);
    EXPECT_TRUE(a.empty());
}

TEST_F(SecureMemoryTest, SecureBufferIteration) {
    SecureBuffer buf(4);
    buf[0] = 1; buf[1] = 2; buf[2] = 3; buf[3] = 4;

    uint8_t sum = 0;
    for (auto byte : buf) {
        sum += byte;
    }
    EXPECT_EQ(sum, 10);
}

TEST_F(SecureMemoryTest, SecureBufferIsNotCopyable) {
    static_assert(!std::is_copy_constructible_v<SecureBuffer>);
    static_assert(!std::is_copy_assignable_v<SecureBuffer>);
}

TEST_F(SecureMemoryTest, SecureBufferIsMoveOnly) {
    static_assert(std::is_move_constructible_v<SecureBuffer>);
    static_assert(std::is_move_assignable_v<SecureBuffer>);
}

// --- ByteArray ---

TEST_F(SecureMemoryTest, ByteArrayIsStdArray) {
    ByteArray<32> arr{};
    EXPECT_EQ(arr.size(), 32u);
    arr[0] = 0xFF;
    EXPECT_EQ(arr[0], 0xFF);
    static_assert(std::is_same_v<ByteArray<32>, std::array<uint8_t, 32>>);
}
