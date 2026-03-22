#include <shatters/protocol/message.hpp>

#include <gtest/gtest.h>

namespace
{

shatters::Channel make_channel(uint8_t fill)
{
    shatters::Channel ch{};
    ch.fill(fill);
    return ch;
}

class ProtocolTest : public ::testing::Test {};

TEST_F(ProtocolTest, PublishRoundTrip)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Publish;
    original.id      = 42;
    original.channel = make_channel(0xAA);
    original.payload = {0x01, 0x02, 0x03};

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    auto& msg = result.value();
    EXPECT_EQ(msg.type, shatters::MessageType::Publish);
    EXPECT_EQ(msg.id, 42u);
    EXPECT_EQ(msg.channel, make_channel(0xAA));
    EXPECT_EQ(msg.payload, (shatters::Bytes{0x01, 0x02, 0x03}));
}

TEST_F(ProtocolTest, SubscribeRoundTrip)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Subscribe;
    original.id      = 1;
    original.channel = make_channel(0xBB);

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Subscribe);
    EXPECT_EQ(result.value().channel, make_channel(0xBB));
    EXPECT_TRUE(result.value().payload.empty());
}

TEST_F(ProtocolTest, UnsubscribeRoundTrip)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Unsubscribe;
    original.id      = 99;
    original.channel = make_channel(0xCC);

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Unsubscribe);
    EXPECT_EQ(result.value().id, 99u);
}

TEST_F(ProtocolTest, AckRoundTrip)
{
    shatters::Message original;
    original.type = shatters::MessageType::Ack;
    original.id   = 7;

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Ack);
    EXPECT_EQ(result.value().id, 7u);
}

TEST_F(ProtocolTest, DataRoundTrip)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Data;
    original.id      = 123;
    original.channel = make_channel(0xDD);
    original.payload = {0xDE, 0xAD, 0xBE, 0xEF};

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    auto& msg = result.value();
    EXPECT_EQ(msg.type, shatters::MessageType::Data);
    EXPECT_EQ(msg.id, 123u);
    EXPECT_EQ(msg.channel, make_channel(0xDD));
    EXPECT_EQ(msg.payload, (shatters::Bytes{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST_F(ProtocolTest, EmptyPayload)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Publish;
    original.id      = 1;
    original.channel = make_channel(0x01);

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().channel, make_channel(0x01));
    EXPECT_TRUE(result.value().payload.empty());
}

TEST_F(ProtocolTest, ZeroChannel)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Publish;
    original.id      = 1;
    original.payload = {0xFF};

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().channel, shatters::Channel{});
    EXPECT_EQ(result.value().payload, shatters::Bytes{0xFF});
}

TEST_F(ProtocolTest, DeserializeTooShort)
{
    shatters::Bytes too_short = {0x01, 0x00};
    auto result = shatters::deserialize(too_short);

    EXPECT_TRUE(result.is_err());
    EXPECT_EQ(result.error().code, shatters::ErrorCode::ProtocolError);
}

TEST_F(ProtocolTest, DeserializeExactMinHeader)
{
    shatters::Bytes exact(38, 0x00);
    exact[0] = shatters::PROTOCOL_VERSION;
    exact[1] = 0x01;
    auto result = shatters::deserialize(exact);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Publish);
    EXPECT_TRUE(result.value().payload.empty());
}

TEST_F(ProtocolTest, LargePayload)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Data;
    original.id      = 500;
    original.channel = make_channel(0xEE);
    original.payload.resize(65536, 0xAB);

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().payload.size(), 65536u);
    EXPECT_EQ(result.value().payload.front(), 0xAB);
    EXPECT_EQ(result.value().payload.back(), 0xAB);
}

TEST_F(ProtocolTest, NackRoundTrip)
{
    shatters::Message original;
    original.type    = shatters::MessageType::Nack;
    original.id      = 10;
    original.channel = make_channel(0xFF);
    original.payload = {'e', 'r', 'r'};

    auto bytes  = shatters::serialize(original);
    auto result = shatters::deserialize(bytes);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Nack);
    EXPECT_EQ(result.value().id, 10u);
    EXPECT_EQ(result.value().channel, make_channel(0xFF));
    EXPECT_EQ(result.value().payload, (shatters::Bytes{'e', 'r', 'r'}));
}

TEST_F(ProtocolTest, FixedHeaderSize)
{
    shatters::Message msg;
    msg.type    = shatters::MessageType::Publish;
    msg.id      = 1;
    msg.channel = make_channel(0x42);

    auto bytes = shatters::serialize(msg);
    EXPECT_EQ(bytes.size(), 38u);
}

}
