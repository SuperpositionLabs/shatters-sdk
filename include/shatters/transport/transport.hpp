#pragma once

#include <shatters/types.hpp>

#include <functional>

namespace shatters
{
    enum class ConnectionState : uint8_t
    {
        Disconnected = 0,
        Connecting,
        Connected,
        Reconnecting,
    };

    using FrameCallback = std::function<void(std::vector<uint8_t> data)>;
    using StateCallback = std::function<void(ConnectionState new_state)>;

    class ITransport
    {
        public:
            virtual ~ITransport() = default;

            virtual Status connect(const std::string& host, uint16_t port) = 0;
            virtual void   disconnect() = 0;

            virtual Status publish(ByteSpan data) = 0;

            virtual ConnectionState state() const = 0;
            virtual bool is_connected() const = 0;
            
            virtual void on_frame(FrameCallback callback) = 0;
            virtual void on_state_change(StateCallback callback) = 0;
    };
}