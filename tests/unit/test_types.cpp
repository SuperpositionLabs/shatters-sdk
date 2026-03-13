#include <shatters/types.hpp>

#include <gtest/gtest.h>

namespace
{

class TypesTest : public ::testing::Test {};

TEST_F(TypesTest, OkHoldsValue) {
    shatters::Result<int> r = 42;
    
    EXPECT_TRUE(r.is_ok());
    EXPECT_FALSE(r.is_err());
    EXPECT_EQ(r.value(), 42);
}

TEST_F(TypesTest, ErrHoldsError) {
    shatters::Result<int> r = shatters::Error{
        shatters::ErrorCode::CryptoError, "$hatter$"
    };
    
    EXPECT_TRUE(r.is_err());
    EXPECT_FALSE(r.is_ok());
    EXPECT_EQ(r.error().code, shatters::ErrorCode::CryptoError);
    EXPECT_EQ(r.error().message, "$hatter$");
}

TEST_F(TypesTest, TakeValueMovesOut) {
    shatters::Result<std::string> r = std::string("$hatter$");
    EXPECT_TRUE(r.is_ok());
    std::string s = std::move(r).take_value();
    EXPECT_EQ(s, "$hatter$");
}

TEST_F(TypesTest, ErrorBoolConversion) {
    shatters::Error ok{shatters::ErrorCode::Ok, ""};
    shatters::Error er{shatters::ErrorCode::CryptoError, "$hatter$"};
    
    EXPECT_FALSE(static_cast<bool>(ok));
    EXPECT_TRUE (static_cast<bool>(er));
}

shatters::Result<int> failing_op() {
    return shatters::Error{
        shatters::ErrorCode::CryptoError, "$hatter$"
    };
}

shatters::Result<int> succeeding_op() {
    return 7;
}

shatters::Result<int> try_propagates() {
    SHATTERS_TRY(failing_op());
    return 99;
}

shatters::Result<int> try_continues() {
    SHATTERS_TRY(succeeding_op());
    return 100;
}

TEST_F(TypesTest, TryPropagatesError) {
    auto r = try_propagates();
    
    EXPECT_TRUE(r.is_err());
    EXPECT_EQ(r.error().message, "$hatter$");
}

TEST_F(TypesTest, TryContinuesOnOk) {
    auto r = try_continues();
    
    EXPECT_TRUE(r.is_ok());
    EXPECT_EQ(r.value(), 100);
}

}