#include <shatters/client.hpp>
#include <shatters/conversation/manager.hpp>
#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/identity/identity.hpp>
#include <shatters/messaging/session.hpp>
#include <shatters/storage/contact_store.hpp>
#include <shatters/storage/database.hpp>
#include <shatters/storage/identity_store.hpp>
#include <shatters/storage/message_store.hpp>
#include <shatters/storage/prekey_store.hpp>
#include <shatters/storage/session_store.hpp>
#include <shatters/transport/quic_transport.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <condition_variable>
#include <mutex>
#include <optional>

namespace shatters
{

struct ShattersClient::Impl
{
    Config config;

    std::unique_ptr<QuicTransport>   transport;
    std::unique_ptr<Session>         session;
    std::unique_ptr<DeadDropService> deaddrop;

    std::optional  <storage::Database>       db;
    std::unique_ptr<storage::IdentityStore>  identity_store;
    std::unique_ptr<storage::ContactStore>   contact_store;
    std::unique_ptr<storage::SessionStore>   session_store;
    std::unique_ptr<storage::MessageStore>   message_store;
    std::unique_ptr<storage::PreKeyStore>    prekey_store;

    std::optional<identity::Identity>      local_identity;
    std::unique_ptr<conversation::Manager> conversation_mgr;

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
        return Error{ErrorCode::CryptoError, "failed to initialize libsodium"};

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
        spdlog::debug("connection state: {}", static_cast<uint8_t>(state));

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

    if (!impl.config.db_path.empty())
    {
        auto db = storage::Database::open(impl.config.db_path, impl.config.db_pass);
        SHATTERS_TRY(db);
        impl.db.emplace(std::move(db).take_value());

        impl.identity_store = std::make_unique<storage::IdentityStore>(*impl.db);
        impl.contact_store  = std::make_unique<storage::ContactStore>(*impl.db);
        impl.session_store  = std::make_unique<storage::SessionStore>(*impl.db);
        impl.message_store  = std::make_unique<storage::MessageStore>(*impl.db);
        impl.prekey_store   = std::make_unique<storage::PreKeyStore>(*impl.db);

        auto id = identity::Identity::load_or_create(*impl.db);
        SHATTERS_TRY(id);
        impl.local_identity.emplace(std::move(id).take_value());

        spdlog::info("local address: {}", impl.local_identity->address().to_string());

        auto mgr = conversation::Manager::create(
            *impl.local_identity,
            *impl.session,
            *impl.db,
            *impl.session_store,
            *impl.contact_store,
            *impl.message_store,
            *impl.prekey_store);
        SHATTERS_TRY(mgr);
        impl.conversation_mgr = std::move(mgr).take_value();
    }

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

const identity::Identity& ShattersClient::identity() const
{
    return *impl_->local_identity;
}

std::string ShattersClient::address() const
{
    return impl_->local_identity->address().to_string();
}

Status ShattersClient::add_contact(const std::string& address, const crypto::PublicKey& public_key, const std::string& display_name)
{
    if (!impl_->contact_store)
        return Error{ErrorCode::InternalError, "no database"};

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    storage::ContactRecord cr
    {
        .address      = address,
        .public_key   = public_key,
        .display_name = display_name,
        .added_at     = now,
    };
    return impl_->contact_store->store(cr);
}

Status ShattersClient::remove_contact(const std::string& address)
{
    if (!impl_->contact_store)
        return Error{ErrorCode::InternalError, "no database"};
    return impl_->contact_store->remove(address);
}

Result<std::vector<storage::ContactRecord>> ShattersClient::list_contacts()
{
    if (!impl_->contact_store)
        return Error{ErrorCode::InternalError, "no database"};
    return impl_->contact_store->list_all();
}

Status ShattersClient::send_message(const std::string& contact_address, ByteSpan plaintext)
{
    if (!impl_->conversation_mgr)
        return Error{ErrorCode::InternalError, "no database"};
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};
    return impl_->conversation_mgr->send(contact_address, plaintext);
}

Status ShattersClient::start_conversation(const std::string& contact_address, const x3dh::PreKeyBundle& their_bundle, ByteSpan first_message)
{
    if (!impl_->conversation_mgr)
        return Error{ErrorCode::InternalError, "no database"};
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};
    return impl_->conversation_mgr->initiate_session(contact_address, their_bundle, first_message);
}

Status ShattersClient::upload_prekey_bundle(uint32_t num_one_time)
{
    if (!impl_->conversation_mgr)
        return Error{ErrorCode::InternalError, "no database"};
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};
    return impl_->conversation_mgr->upload_bundle(num_one_time);
}

Result<x3dh::PreKeyBundle> ShattersClient::fetch_bundle(const std::string& address, std::chrono::seconds timeout)
{
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};

    auto parsed = identity::ContactAddress::from_string(address);
    SHATTERS_TRY(parsed);
    auto intro_ch = parsed.value().intro_channel();

    std::mutex mu;
    std::condition_variable cv;
    std::optional<x3dh::PreKeyBundle> bundle_result;
    bool done = false;

    auto sub_result = subscribe(intro_ch,
        [&](const Channel&, ByteSpan data)
        {
            auto bundle = x3dh::deserialize_bundle(data);
            if (bundle.is_err()) return;

            std::lock_guard lk(mu);
            if (!done)
            {
                bundle_result = std::move(bundle).take_value();
                done = true;
                cv.notify_one();
            }
        });
    SHATTERS_TRY(sub_result);

    auto sub_handle = std::move(sub_result).take_value();

    auto fetch_status = impl_->session->fetch_bundle(intro_ch);
    if (fetch_status.is_err())
    {
        unsubscribe(std::move(sub_handle));
        return fetch_status.error();
    }

    {
        std::unique_lock lk(mu);
        cv.wait_for(lk, timeout, [&] { return done; });
    }

    unsubscribe(std::move(sub_handle));

    if (!done)
        return Error{ErrorCode::Timeout, "bundle fetch timed out"};

    return std::move(*bundle_result);
}

Status ShattersClient::resume_conversations()
{
    if (!impl_->conversation_mgr)
        return Error{ErrorCode::InternalError, "no database"};
    return impl_->conversation_mgr->resume_all();
}

void ShattersClient::on_message(conversation::IncomingCallback callback)
{
    if (impl_->conversation_mgr)
        impl_->conversation_mgr->on_message(std::move(callback));
}

}