#pragma once

#include <shatters/types.hpp>

#include <functional>

namespace shatters
{
    enum class ConnectionState : uint8_t
    {
        Disconnected = 0,
        Connecting = 1,
        HandshakingNoise = 2,
        Authenticating = 3,
        Connected = 4,
    };

    using FrameCallback = std::function<void(std::vector<uint8_t> data)>;
    using StateCallback = std::function<void(ConnectionState new_state)>;

    class ITransport
    {
        public:
            virtual ~ITransport() = default;

            /// Connect to relay server and perform noise nk handshake.
            virtual Result<void> connect(
                const std::string& host, uint16_t port,
                const uint8_t* server_pk, size_t pk_len
            ) = 0;
            
            virtual void disconnect() = 0;

            /// Send a frame noise-encrypted before transmission.
            virtual Result<void> send(const uint8_t* data, size_t len) = 0;

            virtual ConnectionState state() const = 0;
            virtual bool is_connected() const = 0;
            
            virtual void on_frame(FrameCallback callback) = 0;
            virtual void on_state_change(StateCallback callback) = 0;
    };
}