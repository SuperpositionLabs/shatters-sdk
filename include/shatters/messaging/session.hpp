#pragma once

#include <shatters/messaging/subscription.hpp>
#include <shatters/transport/transport.hpp>
#include <shatters/types.hpp>

#include <functional>
#include <memory>

namespace shatters
{

class Session
{
public:
    explicit Session(ITransport& transport);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    Status                     publish(const Channel& channel, ByteSpan data);
    Result<SubscriptionHandle> subscribe(const Channel& channel, MessageCallback callback);
    Status                     unsubscribe(SubscriptionId id);

    Status                     retrieve(const Channel& channel, ByteSpan payload);
    Status                     upload_bundle(const Channel& channel, ByteSpan payload);
    Status                     fetch_bundle(const Channel& channel);

    using ErrorCallback = std::function<void(Error)>;
    void on_error(ErrorCallback callback);

    void resubscribe_all();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
