#include <shatters/messaging/session.hpp>
#include <shatters/protocol/message.hpp>
#include <shatters/crypto/keys.hpp>

#include <gtest/gtest.h>

#include <mutex>
#include <set>
#include <vector>

namespace
{

shatters::Channel make_channel(uint8_t fill)
{
    shatters::Channel ch{};
    ch.fill(fill);
    return ch;
}

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

class SessionTest : public ::testing::Test
{
protected:
    MockTransport transport;
};

TEST_F(SessionTest, PublishSendsMessage)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto kp_result = shatters::crypto::IdentityKeyPair::generate();
    ASSERT_TRUE(kp_result.is_ok());
    auto kp = std::move(kp_result).take_value();
    session.set_identity(&kp);

    auto ch = make_channel(0x01);
    std::string payload_str = "hello";
    shatters::ByteSpan payload(
        reinterpret_cast<const uint8_t*>(payload_str.data()),
        payload_str.size());

    auto status = session.publish(ch, payload);
    ASSERT_TRUE(status.is_ok());

    auto sent = transport.take_sent();
    ASSERT_EQ(sent.size(), 1u);

    auto result = shatters::deserialize(sent[0]);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Publish);
    EXPECT_EQ(result.value().channel, ch);
}

TEST_F(SessionTest, SubscribeSendsMessage)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto ch = make_channel(0x02);
    auto sub = session.subscribe(ch,
        [](const shatters::Channel&, shatters::ByteSpan) {});

    ASSERT_TRUE(sub.is_ok());
    EXPECT_TRUE(sub.value().valid());

    auto sent = transport.take_sent();
    ASSERT_EQ(sent.size(), 1u);

    auto result = shatters::deserialize(sent[0]);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Subscribe);
    EXPECT_EQ(result.value().channel, ch);
}

TEST_F(SessionTest, ReceiveDataDispatchesToSubscriber)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto ch = make_channel(0x03);
    shatters::Channel          received_channel{};
    std::vector<uint8_t>       received_payload;

    auto sub = session.subscribe(ch,
        [&](const shatters::Channel& channel, shatters::ByteSpan payload) {
            received_channel = channel;
            received_payload.assign(payload.begin(), payload.end());
        });

    ASSERT_TRUE(sub.is_ok());
    transport.take_sent();

    shatters::Message data_msg;
    data_msg.type    = shatters::MessageType::Data;
    data_msg.id      = 1;
    data_msg.channel = ch;
    data_msg.payload = {0x01, 0x02, 0x03};

    transport.inject_frame(shatters::serialize(data_msg));

    EXPECT_EQ(received_channel, ch);
    EXPECT_EQ(received_payload, (std::vector<uint8_t>{0x01, 0x02, 0x03}));
}

TEST_F(SessionTest, UnsubscribeStopsDelivery)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto ch = make_channel(0x04);
    int call_count = 0;
    auto sub = session.subscribe(ch,
        [&](const shatters::Channel&, shatters::ByteSpan) { ++call_count; });

    ASSERT_TRUE(sub.is_ok());
    auto sub_id = sub.value().id();

    auto status = session.unsubscribe(sub_id);
    EXPECT_TRUE(status.is_ok());
    sub.value().release();

    shatters::Message data_msg;
    data_msg.type    = shatters::MessageType::Data;
    data_msg.id      = 1;
    data_msg.channel = ch;
    data_msg.payload = {0xFF};

    transport.inject_frame(shatters::serialize(data_msg));

    EXPECT_EQ(call_count, 0);
}

TEST_F(SessionTest, HandleAutoUnsubscribesOnDestruction)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto ch = make_channel(0x05);

    {
        auto sub = session.subscribe(ch,
            [](const shatters::Channel&, shatters::ByteSpan) {});
        ASSERT_TRUE(sub.is_ok());
        transport.take_sent();
    }

    auto sent = transport.take_sent();
    ASSERT_EQ(sent.size(), 1u);

    auto result = shatters::deserialize(sent[0]);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(result.value().type, shatters::MessageType::Unsubscribe);
    EXPECT_EQ(result.value().channel, ch);
}

TEST_F(SessionTest, MultipleSubscribersSameChannel)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto ch = make_channel(0x06);
    int count1 = 0, count2 = 0;

    auto sub1 = session.subscribe(ch,
        [&](const shatters::Channel&, shatters::ByteSpan) { ++count1; });
    auto sub2 = session.subscribe(ch,
        [&](const shatters::Channel&, shatters::ByteSpan) { ++count2; });

    ASSERT_TRUE(sub1.is_ok());
    ASSERT_TRUE(sub2.is_ok());

    shatters::Message data_msg;
    data_msg.type    = shatters::MessageType::Data;
    data_msg.id      = 1;
    data_msg.channel = ch;
    data_msg.payload = {0x01};

    transport.inject_frame(shatters::serialize(data_msg));

    EXPECT_EQ(count1, 1);
    EXPECT_EQ(count2, 1);
}

TEST_F(SessionTest, ResubscribeAllSendsAllChannels)
{
    shatters::Session session(transport);
    transport.connect("localhost", 4433);

    auto ch_a = make_channel(0x0A);
    auto ch_b = make_channel(0x0B);

    auto sub1 = session.subscribe(ch_a,
        [](const shatters::Channel&, shatters::ByteSpan) {});
    auto sub2 = session.subscribe(ch_b,
        [](const shatters::Channel&, shatters::ByteSpan) {});

    ASSERT_TRUE(sub1.is_ok());
    ASSERT_TRUE(sub2.is_ok());
    transport.take_sent();

    session.resubscribe_all();

    auto sent = transport.take_sent();
    ASSERT_EQ(sent.size(), 2u);

    std::set<shatters::Channel> channels;
    for (auto& frame : sent)
    {
        auto result = shatters::deserialize(frame);
        ASSERT_TRUE(result.is_ok());
        EXPECT_EQ(result.value().type, shatters::MessageType::Subscribe);
        channels.insert(result.value().channel);
    }

    EXPECT_TRUE(channels.count(ch_a));
    EXPECT_TRUE(channels.count(ch_b));
}

TEST_F(SessionTest, HandleSurvivesSessionDestruction)
{
    shatters::SubscriptionHandle handle;

    {
        shatters::Session session(transport);
        transport.connect("localhost", 4433);

        auto ch = make_channel(0x0C);
        auto sub = session.subscribe(ch,
            [](const shatters::Channel&, shatters::ByteSpan) {});
        ASSERT_TRUE(sub.is_ok());
        handle = std::move(sub.value());
    }
}

}
