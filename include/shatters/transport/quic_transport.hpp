#pragma once

#include <shatters/transport/transport.hpp>

namespace shatters
{
    class QuicTransport : public ITransport
    {
        public:
            struct Config
            {
                std::string tls_alpn = "$hatter$/1";
                std::vector<uint8_t> tls_pin_sha256;

                uint32_t idle_timeout_ms = 60000;
                uint32_t keep_alive_ms = 15000;

                bool auto_reconnect = true;
                uint32_t reconnect_delay_ms = 500;
                uint32_t max_reconnect_delay_ms = 30000;
            };

            explicit QuicTransport(Config config);
            ~QuicTransport() override;

            Status connect(const std::string& host, uint16_t port) override;
            void   disconnect() override;

            Status publish(ByteSpan data) override;

            ConnectionState state() const override;
            bool is_connected() const override;

            void on_frame(FrameCallback callback) override;
            void on_state_change(StateCallback callback) override;

            QuicTransport(const QuicTransport&) = delete;
            QuicTransport& operator=(const QuicTransport&) = delete;
        
        private:
            void schedule_reconnect();

            struct Impl;
            std::unique_ptr<Impl> impl_;
    };
}
