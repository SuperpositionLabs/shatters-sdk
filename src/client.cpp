#include <shatters/client.hpp>
#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/messaging/session.hpp>
#include <shatters/transport/quic_transport.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <mutex>

namespace shatters
{

struct ShattersClient::Impl
{
    Config config;

    std::unique_ptr<QuicTransport>   transport;
    std::unique_ptr<Session>         session;
    std::unique_ptr<DeadDropService> deaddrop;

    std::mutex                 callback_mutex;
    std::function<void()>      on_connected_cb;
    std::function<void(Error)> on_disconnected_cb;
};

ShattersClient::ShattersClient() : impl_(std::make_unique<Impl>()) {}

ShattersClient::~ShattersClient()
{
    disconnect();
}

Result<std::unique_ptr<ShattersClient>> ShattersClient::create(Config config)
{
    if (sodium_init() < 0)
        return std::unexpected(
            Error{ErrorCode::CryptoError, "failed to initialize libsodium"});

    auto client = std::unique_ptr<ShattersClient>(new ShattersClient());
    auto& impl  = *client->impl_;
    impl.config = std::move(config);

    QuicTransport::Config quic_config;
    quic_config.tls_pin_sha256 = impl.config.tls_pin_sha256;
    quic_config.auto_reconnect = impl.config.auto_reconnect;

    impl.transport = std::make_unique<QuicTransport>(std::move(quic_config));

    impl.session  = std::make_unique<Session>(*impl.transport);
    impl.deaddrop = std::make_unique<DeadDropService>(*impl.session);

    impl.transport->on_state_change([&impl](ConnectionState state)
    {
        spdlog::info("connection state: {}", static_cast<uint8_t>(state));

        std::lock_guard lock(impl.callback_mutex);

        if (state == ConnectionState::Connected)
        {
            impl.session->resubscribe_all();
            if (impl.on_connected_cb)
                impl.on_connected_cb();
        }
        else if (state == ConnectionState::Disconnected)
        {
            if (impl.on_disconnected_cb)
                impl.on_disconnected_cb(
                    Error{ErrorCode::ConnectionClosed, "disconnected"});
        }
    });

    return std::move(client);
}

Status ShattersClient::connect()
{
    return impl_->transport->connect(
        impl_->config.server_host,
        impl_->config.server_port
    );
}

void ShattersClient::disconnect()
{
    if (impl_ && impl_->transport)
        impl_->transport->disconnect();
}

bool ShattersClient::is_connected() const
{
    return impl_->transport && impl_->transport->is_connected();
}

Status ShattersClient::publish(const Channel& channel, ByteSpan data)
{
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};
    return impl_->session->publish(channel, data);
}

Result<SubscriptionHandle> ShattersClient::subscribe(const Channel& channel, MessageCallback callback)
{
    return impl_->session->subscribe(channel, std::move(callback));
}

Status ShattersClient::unsubscribe(SubscriptionHandle&& handle)
{
    if (!handle.valid())
        return Status{};

    auto id = handle.id();
    handle.release();
    return impl_->session->unsubscribe(id);
}

void ShattersClient::on_connected(std::function<void()> callback)
{
    std::lock_guard lock(impl_->callback_mutex);
    impl_->on_connected_cb = std::move(callback);
}

void ShattersClient::on_disconnected(std::function<void(Error)> callback)
{
    std::lock_guard lock(impl_->callback_mutex);
    impl_->on_disconnected_cb = std::move(callback);
}

void ShattersClient::on_error(std::function<void(Error)> callback)
{
    impl_->session->on_error(std::move(callback));
}

Status ShattersClient::drop(const DeadDropId& id, ByteSpan ciphertext)
{
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};
    return impl_->deaddrop->drop(id, ciphertext);
}

Result<DeadDropHandle> ShattersClient::watch(const DeadDropId& id, DeadDropCallback cb)
{
    return impl_->deaddrop->watch(id, std::move(cb));
}

Status ShattersClient::unwatch(DeadDropHandle&& handle)
{
    return impl_->deaddrop->unwatch(std::move(handle));
}

Status ShattersClient::retrieve(const DeadDropId& id, std::chrono::seconds ttl_hint, DeadDropCallback cb)
{
    return impl_->deaddrop->retrieve(id, ttl_hint, std::move(cb));
}

}