#include <shatters/transport/quic_transport.hpp>

#include <sodium.h>
#include <gtest/gtest.h>

namespace
{

class QuicTransportTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            ASSERT_GE(sodium_init(), -1);
            crypto_kx_keypair(server_pk, server_sk);
            transport = std::make_unique<shatters::QuicTransport>(shatters::QuicTransport::Config{});
        }

        void TearDown() override
        {
            transport.reset();
        }

        uint8_t server_pk[crypto_kx_PUBLICKEYBYTES]{};
        uint8_t server_sk[crypto_kx_SECRETKEYBYTES]{};
       
        std::unique_ptr<shatters::QuicTransport> transport;
};

TEST_F(QuicTransportTest, InitialState) 
{
    EXPECT_EQ(transport->state(), shatters::ConnectionState::Disconnected);
    EXPECT_FALSE(transport->is_connected());
}

TEST_F(QuicTransportTest, SendWhileDisconnected)
{
    uint8_t data[] = "hello";
    auto result = transport->send(data, sizeof(data));

    EXPECT_TRUE(result.is_err());
    EXPECT_EQ(result.error().code, shatters::ErrorCode::NetworkError);
}

TEST_F(QuicTransportTest, DisconnectWhileAlreadyDisconnected)
{
    transport->disconnect();
    EXPECT_EQ(transport->state(), shatters::ConnectionState::Disconnected);
}

TEST_F(QuicTransportTest, CallbacksCanBeSet)
{
    bool frame_cb_called = false;
    bool state_cb_called = false;

    transport->on_frame([&](std::vector<uint8_t>)             { frame_cb_called = true; });
    transport->on_state_change([&](shatters::ConnectionState) { state_cb_called = true; });

    EXPECT_FALSE(frame_cb_called);
    EXPECT_FALSE(state_cb_called);
}

}
