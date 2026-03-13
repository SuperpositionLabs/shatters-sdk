#include <shatters/client.hpp>
#include <shatters/transport/quic_transport.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

namespace shatters
{
    struct ShattersClient::Impl
    {
        Config config;

        std::unique_ptr<QuicTransport> transport;
    };

    ShattersClient::ShattersClient() : impl_(std::make_unique<Impl>()) {}

    ShattersClient::~ShattersClient() 
    {
        disconnect();
    }

    Result<std::unique_ptr<ShattersClient>> ShattersClient::create(Config config)
    {
        if (sodium_init() < 0)
            return Error{ErrorCode::CryptoError, "failed to initialize libsodium"};

        auto client = std::unique_ptr<ShattersClient>(new ShattersClient());
        
        auto& impl = *client->impl_;
        impl.config = std::move(config);

        QuicTransport::Config quic_config;
        quic_config.tls_pin_sha256 = impl.config.tls_pin_sha256;
        quic_config.auto_reconnect = impl.config.auto_reconnect;

        impl.transport = std::make_unique<QuicTransport>(std::move(quic_config));

        impl.transport->on_frame([&impl](std::vector<uint8_t> data)
        {
            spdlog::info("received frame ({} bytes)", data.size());
        });

        impl.transport->on_state_change([&impl](ConnectionState state)
        {
            spdlog::info("state changed to {}", static_cast<uint8_t>(state));
        });

        return std::move(client);
    }

    Result<void> ShattersClient::connect()
    {
        return impl_->transport->connect(
            impl_->config.server_host,
            impl_->config.server_port,
            impl_->config.server_pubkey.data(),
            impl_->config.server_pubkey.size()
        );
    }

    void ShattersClient::disconnect()
    {
        if (impl_->transport)
            impl_->transport->disconnect();
    }

    bool ShattersClient::is_connected() const
    {
        return impl_->transport && impl_->transport->is_connected();
    }
}