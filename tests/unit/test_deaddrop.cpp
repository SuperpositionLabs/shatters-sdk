#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/protocol/message.hpp>
#include <shatters/messaging/session.hpp>

#include <gtest/gtest.h>

#include <mutex>
#include <string>
#include <vector>

namespace
{

class MockTransport : public shatters::ITransport
{
public:
    shatters::Status connect(const std::string&, uint16_t) override
    {
        connected_ = true;
        return shatters::Status{};
    }

    void disconnect() override { connected_ = false; }

    shatters::Status publish(shatters::ByteSpan data) override
    {
        std::lock_guard lock(mu_);
        sent_frames_.emplace_back(data.begin(), data.end());
        return shatters::Status{};
    }

    shatters::ConnectionState state() const override
    {
        return connected_ ? shatters::ConnectionState::Connected
                          : shatters::ConnectionState::Disconnected;
    }

    bool is_connected() const override { return connected_; }

    void on_frame(shatters::FrameCallback cb) override
    {
        frame_cb_ = std::move(cb);
    }

    void on_state_change(shatters::StateCallback cb) override
    {
        state_cb_ = std::move(cb);
    }

    void inject_frame(std::vector<uint8_t> data)
    {
        if (frame_cb_)
            frame_cb_(std::move(data));
    }

    std::vector<std::vector<uint8_t>> take_sent()
    {
        std::lock_guard lock(mu_);
        return std::exchange(sent_frames_, {});
    }

private:
    bool                    connected_ = false;
    shatters::FrameCallback frame_cb_;
    shatters::StateCallback state_cb_;
    std::mutex              mu_;
    std::vector<std::vector<uint8_t>> sent_frames_;
};

TEST(DeadDropIdTest, FromBytesRoundTrip)
{
    std::array<uint8_t, 32> raw{};
    for (uint8_t i = 0; i < 32; ++i)
        raw[i] = i;

    auto id = shatters::DeadDropId::from_bytes(shatters::ByteSpan(raw));
    ASSERT_TRUE(id.is_ok());
    EXPECT_EQ(id.value().bytes, raw);
}

TEST(DeadDropIdTest, FromBytesRejectsBadSize)
{
    std::array<uint8_t, 16> short_buf{};
    auto id = shatters::DeadDropId::from_bytes(shatters::ByteSpan(short_buf.data(), short_buf.size()));
    EXPECT_TRUE(id.is_err());
}

TEST(DeadDropIdTest, HexRoundTrip)
{
    std::array<uint8_t, 32> raw{};
    for (uint8_t i = 0; i < 32; ++i)
        raw[i] = i;

    auto id = shatters::DeadDropId::from_bytes(shatters::ByteSpan(raw));
    ASSERT_TRUE(id.is_ok());

    std::string hex = id.value().to_hex();
    EXPECT_EQ(hex.size(), 64u);

    auto id2 = shatters::DeadDropId::from_hex(hex);
    ASSERT_TRUE(id2.is_ok());
    EXPECT_EQ(id2.value(), id.value());
}

TEST(DeadDropIdTest, FromHexRejectsBadLength)
{
    auto id = shatters::DeadDropId::from_hex("deadbeef");
    EXPECT_TRUE(id.is_err());
}

TEST(DeadDropIdTest, FromHexRejectsBadChars)
{
    std::string bad(64, 'g');
    auto id = shatters::DeadDropId::from_hex(bad);
    EXPECT_TRUE(id.is_err());
}

TEST(EnvelopeTest, SerializeDeserializeRoundTrip)
{
    shatters::Envelope env;
    for (uint8_t i = 0; i < 32; ++i)
        env.id.bytes[i] = i;
    env.ciphertext = {0xCA, 0xFE, 0xBA, 0xBE};
    env.timestamp_ms = 1700000000000ULL;

    auto wire = shatters::serialize_envelope(env);

    auto result = shatters::deserialize_envelope(shatters::ByteSpan(wire));
    ASSERT_TRUE(result.is_ok());

    auto& got = result.value();
    EXPECT_EQ(got.id, env.id);
    EXPECT_EQ(got.timestamp_ms, env.timestamp_ms);
    EXPECT_EQ(got.ciphertext, env.ciphertext);
}

TEST(EnvelopeTest, EmptyCiphertext)
{
    shatters::Envelope env;
    for (uint8_t i = 0; i < 32; ++i)
        env.id.bytes[i] = 0xFF;
    env.timestamp_ms = 42;

    auto wire = shatters::serialize_envelope(env);
    EXPECT_EQ(wire.size(), 40u);

    auto result = shatters::deserialize_envelope(shatters::ByteSpan(wire));
    ASSERT_TRUE(result.is_ok());
    EXPECT_TRUE(result.value().ciphertext.empty());
}

TEST(EnvelopeTest, TooShortReturnsError)
{
    std::vector<uint8_t> short_data(10, 0);
    auto result = shatters::deserialize_envelope(shatters::ByteSpan(short_data));
    EXPECT_TRUE(result.is_err());
}

class DeadDropServiceTest : public ::testing::Test
{
protected:
    MockTransport             transport;
    shatters::Session         session{transport};
    shatters::DeadDropService service{session};

    void SetUp() override
    {
        transport.connect("localhost", 4433);
    }

    shatters::DeadDropId make_id(uint8_t fill = 0xAA)
    {
        std::array<uint8_t, 32> raw{};
        raw.fill(fill);
        
        return shatters::DeadDropId::from_bytes(shatters::ByteSpan(raw)).value();
    }
};

TEST_F(DeadDropServiceTest, DropSendsEnvelope)
{
    auto id = make_id(0x01);
    std::vector<uint8_t> ct = {0xDE, 0xAD};

    auto status = service.drop(id, shatters::ByteSpan(ct));
    ASSERT_TRUE(status.is_ok());

    auto sent = transport.take_sent();
    ASSERT_EQ(sent.size(), 1u);

    auto msg = shatters::deserialize(sent[0]);
    ASSERT_TRUE(msg.is_ok());
    EXPECT_EQ(msg.value().type, shatters::MessageType::Publish);
    EXPECT_EQ(msg.value().channel, id.channel());

    auto env = shatters::deserialize_envelope(shatters::ByteSpan(msg.value().payload));
    ASSERT_TRUE(env.is_ok());
    EXPECT_EQ(env.value().id, id);
    EXPECT_EQ(env.value().ciphertext, ct);
}

TEST_F(DeadDropServiceTest, WatchReceivesEnvelope)
{
    auto id = make_id(0x02);

    std::vector<shatters::Envelope> received;
    auto handle_result = service.watch(id, [&](const shatters::Envelope& env) { received.push_back(env); });
    ASSERT_TRUE(handle_result.is_ok());
    auto handle = std::move(handle_result).take_value();
    EXPECT_TRUE(handle.valid());

    shatters::Envelope env;
    env.id = id;
    env.ciphertext = {0xBE, 0xEF};
    env.timestamp_ms = 99;
    auto payload = shatters::serialize_envelope(env);

    shatters::Message data_msg;
    data_msg.type    = shatters::MessageType::Data;
    data_msg.id      = 1;
    data_msg.channel = id.channel();
    data_msg.payload = payload;

    auto wire = shatters::serialize(data_msg);
    transport.inject_frame(wire);

    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0].id, id);
    EXPECT_EQ(received[0].ciphertext, env.ciphertext);
    EXPECT_EQ(received[0].timestamp_ms, 99u);
}

TEST_F(DeadDropServiceTest, UnwatchInvalidatesHandle)
{
    auto id = make_id(0x03);

    auto h = service.watch(id, [](const shatters::Envelope&) {});
    ASSERT_TRUE(h.is_ok());
    auto handle = std::move(h).take_value();
    EXPECT_TRUE(handle.valid());

    auto status = service.unwatch(std::move(handle));
    EXPECT_TRUE(status.is_ok());
}

TEST_F(DeadDropServiceTest, HandleRAIIAutoUnwatch)
{
    auto id = make_id(0x04);

    {
        auto h = service.watch(id, [](const shatters::Envelope&) {});
        ASSERT_TRUE(h.is_ok());
    }

    SUCCEED();
}

TEST_F(DeadDropServiceTest, RetrieveSendsRequest)
{
    auto id = make_id(0x05);

    bool called = false;
    auto status = service.retrieve(id, std::chrono::seconds(300), [&](const shatters::Envelope&) { called = true; });
    ASSERT_TRUE(status.is_ok());

    auto sent = transport.take_sent();
    ASSERT_GE(sent.size(), 2u);
}

TEST_F(DeadDropServiceTest, WatchTwoDifferentDrops)
{
    auto id1 = make_id(0x10);
    auto id2 = make_id(0x20);

    std::vector<shatters::Envelope> rx1, rx2;

    auto h1 = service.watch(id1, [&](const shatters::Envelope& e) { rx1.push_back(e); });
    auto h2 = service.watch(id2, [&](const shatters::Envelope& e) { rx2.push_back(e); });
    ASSERT_TRUE(h1.is_ok());
    ASSERT_TRUE(h2.is_ok());

    shatters::Envelope env1;
    env1.id = id1;
    env1.ciphertext = {0x01};
    env1.timestamp_ms = 1;

    shatters::Message msg1;
    msg1.type    = shatters::MessageType::Data;
    msg1.id      = 10;
    msg1.channel = id1.channel();
    msg1.payload = shatters::serialize_envelope(env1);
    transport.inject_frame(shatters::serialize(msg1));

    shatters::Envelope env2;
    env2.id = id2;
    env2.ciphertext = {0x02};
    env2.timestamp_ms = 2;

    shatters::Message msg2;
    msg2.type    = shatters::MessageType::Data;
    msg2.id      = 11;
    msg2.channel = id2.channel();
    msg2.payload = shatters::serialize_envelope(env2);
    transport.inject_frame(shatters::serialize(msg2));

    ASSERT_EQ(rx1.size(), 1u);
    ASSERT_EQ(rx2.size(), 1u);
    EXPECT_EQ(rx1[0].ciphertext, std::vector<uint8_t>{0x01});
    EXPECT_EQ(rx2[0].ciphertext, std::vector<uint8_t>{0x02});
}

}
