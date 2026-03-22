#include <shatters/messaging/session.hpp>
#include <shatters/auth/auth.hpp>
#include <shatters/protocol/message.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace shatters
{

SubscriptionHandle::SubscriptionHandle(SubscriptionId id, Session* session, std::weak_ptr<bool> alive)
    : id_(id)
    , session_(session)
    , alive_(std::move(alive))
{
}

SubscriptionHandle::~SubscriptionHandle()
{
    if (session_ && id_ != 0 && alive_.lock())
        session_->unsubscribe(id_);
}

SubscriptionHandle::SubscriptionHandle(SubscriptionHandle&& other) noexcept
    : id_(other.id_)
    , session_(other.session_)
    , alive_(std::move(other.alive_))
{
    other.id_      = 0;
    other.session_ = nullptr;
}

SubscriptionHandle& SubscriptionHandle::operator=(SubscriptionHandle&& other) noexcept
{
    if (this != &other)
    {
        if (session_ && id_ != 0 && alive_.lock())
            session_->unsubscribe(id_);

        id_      = other.id_;
        session_ = other.session_;
        alive_   = std::move(other.alive_);

        other.id_      = 0;
        other.session_ = nullptr;
    }
    return *this;
}

void SubscriptionHandle::release() noexcept
{
    id_      = 0;
    session_ = nullptr;
    alive_.reset();
}

struct SubscriptionEntry
{
    Channel         channel;
    MessageCallback callback;
};

struct Session::Impl
{
    ITransport& transport;
    const crypto::IdentityKeyPair* identity{nullptr};

    std::atomic<uint32_t> next_msg_id{1};
    std::atomic<uint64_t> next_sub_id{1};

    std::shared_ptr<bool> alive = std::make_shared<bool>(true);

    mutable std::shared_mutex sub_mutex;
    std::unordered_map<SubscriptionId, SubscriptionEntry> subscriptions;
    std::unordered_map<Channel, std::vector<SubscriptionId>, ChannelHash> channel_index;

    std::mutex    error_mutex;
    ErrorCallback on_error_cb;

    explicit Impl(ITransport& t) : transport(t) {}

    uint32_t alloc_msg_id() { return next_msg_id.fetch_add(1, std::memory_order_relaxed); }
    uint64_t alloc_sub_id() { return next_sub_id.fetch_add(1, std::memory_order_relaxed); }

    void dispatch_data(const Message& msg)
    {
        std::shared_lock lock(sub_mutex);
        auto it = channel_index.find(msg.channel);
        if (it == channel_index.end())
            return;

        for (auto sub_id : it->second)
        {
            auto sit = subscriptions.find(sub_id);
            if (sit != subscriptions.end() && sit->second.callback)
            {
                ByteSpan payload(msg.payload);
                sit->second.callback(msg.channel, payload);
            }
        }
    }

    void dispatch_error(const Message& msg)
    {
        std::lock_guard lock(error_mutex);
        if (on_error_cb)
        {
            Error err{ErrorCode::ProtocolError, std::string(msg.payload.begin(), msg.payload.end())};
            on_error_cb(std::move(err));
        }
    }

    void handle_frame(std::vector<uint8_t> raw)
    {
        auto result = shatters::deserialize(ByteSpan(raw));
        if (result.is_err())
        {
            spdlog::warn("failed to deserialize message: {}", result.error().message);
            return;
        }

        auto& msg = result.value();

        switch (msg.type)
        {
            case MessageType::Data:
                dispatch_data(msg);
                break;

            case MessageType::Ack:
                spdlog::debug("received ack for msg_id={}", msg.id);
                break;

            case MessageType::Nack:
                spdlog::warn("received nack for msg_id={}: {}", msg.id, std::string(msg.payload.begin(), msg.payload.end()));
                dispatch_error(msg);
                break;

            case MessageType::BundleData:
                dispatch_data(msg);
                break;

            default:
                spdlog::debug("received message type=0x{:02x} id={}", static_cast<uint8_t>(msg.type), msg.id);
                break;
        }
    }

    Status send_message(const Message& msg)
    {
        auto serialized = shatters::serialize(msg);
        return transport.publish(ByteSpan(serialized));
    }
};

Session::Session(ITransport& transport) : impl_(std::make_unique<Impl>(transport))
{
    transport.on_frame([this](std::vector<uint8_t> data)
    {
        impl_->handle_frame(std::move(data));
    });
}

Session::~Session() = default;

void Session::set_identity(const crypto::IdentityKeyPair* kp)
{
    impl_->identity = kp;
}

Status Session::authenticate()
{
    if (!impl_->identity)
        return Error{ErrorCode::InternalError, "no identity set for authentication"};

    auto payload = auth::build_auth_payload(*impl_->identity);
    SHATTERS_TRY(payload);

    Message msg;
    msg.type    = MessageType::Authenticate;
    msg.id      = impl_->alloc_msg_id();
    msg.payload = std::move(payload).take_value();

    return impl_->send_message(msg);
}

Status Session::publish(const Channel& channel, ByteSpan data)
{
    if (!impl_->identity)
        return Error{ErrorCode::InternalError, "no identity set"};

    auto proof = auth::build_channel_proof(*impl_->identity, channel, data);
    SHATTERS_TRY(proof);

    Message msg;
    msg.type    = MessageType::Publish;
    msg.id      = impl_->alloc_msg_id();
    msg.channel = channel;
    msg.payload = std::move(proof).take_value();

    return impl_->send_message(msg);
}

Result<SubscriptionHandle> Session::subscribe(const Channel& channel, MessageCallback callback)
{
    auto sub_id = impl_->alloc_sub_id();

    {
        std::unique_lock lock(impl_->sub_mutex);
        impl_->subscriptions[sub_id] = SubscriptionEntry{channel, std::move(callback)};
        impl_->channel_index[channel].push_back(sub_id);
    }

    Message msg;
    msg.type    = MessageType::Subscribe;
    msg.id      = impl_->alloc_msg_id();
    msg.channel = channel;

    if (impl_->identity)
    {
        auto proof = auth::build_channel_proof(*impl_->identity, channel);
        if (proof.is_err())
        {
            std::unique_lock lock(impl_->sub_mutex);
            impl_->subscriptions.erase(sub_id);
            auto& idx = impl_->channel_index[channel];
            idx.erase(std::remove(idx.begin(), idx.end(), sub_id), idx.end());
            if (idx.empty())
                impl_->channel_index.erase(channel);
            return proof.error();
        }
        msg.payload = std::move(proof).take_value();
    }

    auto status = impl_->send_message(msg);
    if (status.is_err())
    {
        std::unique_lock lock(impl_->sub_mutex);
        impl_->subscriptions.erase(sub_id);
        auto& idx = impl_->channel_index[channel];
        idx.erase(std::remove(idx.begin(), idx.end(), sub_id), idx.end());
        if (idx.empty())
            impl_->channel_index.erase(channel);
        return status.error();
    }

    return SubscriptionHandle(sub_id, this, impl_->alive);
}

Status Session::unsubscribe(SubscriptionId id)
{
    Channel channel{};

    {
        std::unique_lock lock(impl_->sub_mutex);
        auto it = impl_->subscriptions.find(id);
        if (it == impl_->subscriptions.end())
            return Status{};

        channel = it->second.channel;
        impl_->subscriptions.erase(it);

        auto& idx = impl_->channel_index[channel];
        idx.erase(std::remove(idx.begin(), idx.end(), id), idx.end());
        if (idx.empty())
            impl_->channel_index.erase(channel);
    }

    Message msg;
    msg.type    = MessageType::Unsubscribe;
    msg.id      = impl_->alloc_msg_id();
    msg.channel = channel;

    impl_->send_message(msg);
    return Status{};
}

Status Session::retrieve(const Channel& channel, ByteSpan data)
{
    if (!impl_->identity)
        return Error{ErrorCode::InternalError, "no identity set"};

    auto proof = auth::build_channel_proof(*impl_->identity, channel, data);
    SHATTERS_TRY(proof);

    Message msg;
    msg.type    = MessageType::Retrieve;
    msg.id      = impl_->alloc_msg_id();
    msg.channel = channel;
    msg.payload = std::move(proof).take_value();

    return impl_->send_message(msg);
}

Status Session::upload_bundle(const Channel& channel, ByteSpan payload)
{
    if (!impl_->identity)
        return Error{ErrorCode::InternalError, "no identity set"};

    auto proof = auth::build_channel_proof(*impl_->identity, channel, payload);
    SHATTERS_TRY(proof);

    Message msg;
    msg.type    = MessageType::UploadBundle;
    msg.id      = impl_->alloc_msg_id();
    msg.channel = channel;
    msg.payload = std::move(proof).take_value();

    return impl_->send_message(msg);
}

Status Session::fetch_bundle(const Channel& channel)
{
    Message msg;
    msg.type    = MessageType::FetchBundle;
    msg.id      = impl_->alloc_msg_id();
    msg.channel = channel;

    return impl_->send_message(msg);
}

void Session::on_error(ErrorCallback callback)
{
    std::lock_guard lock(impl_->error_mutex);
    impl_->on_error_cb = std::move(callback);
}

void Session::resubscribe_all()
{
    if (impl_->identity)
    {
        auto auth_status = authenticate();
        if (auth_status.is_err())
            spdlog::warn("failed to re-authenticate: {}", auth_status.error().message);
    }

    std::vector<Channel> channels;

    {
        std::shared_lock lock(impl_->sub_mutex);
        channels.reserve(impl_->channel_index.size());
        for (auto& [ch, _] : impl_->channel_index)
            channels.push_back(ch);
    }

    for (auto& ch : channels)
    {
        Message msg;
        msg.type    = MessageType::Subscribe;
        msg.id      = impl_->alloc_msg_id();
        msg.channel = ch;

        if (impl_->identity)
        {
            auto proof = auth::build_channel_proof(*impl_->identity, ch);
            if (proof.is_ok())
                msg.payload = std::move(proof).take_value();
            else
                spdlog::warn("failed to build channel proof for resubscribe");
        }

        auto status = impl_->send_message(msg);
        if (status.is_err())
            spdlog::warn("failed to resubscribe: {}", status.error().message);
    }
}

}