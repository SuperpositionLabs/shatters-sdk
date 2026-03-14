#pragma once

#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/messaging/subscription.hpp>
#include <shatters/types.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <string>

namespace shatters
{

class ShattersClient
{
public:
    struct Config
    {
        std::string db_path;
        std::string db_pass;

        std::string          server_host;
        uint16_t             server_port = 443;
        std::vector<uint8_t> server_static_key;

        std::vector<uint8_t> tls_pin_sha256;

        bool auto_reconnect = true;
    };

    ~ShattersClient();

    static Result<std::unique_ptr<ShattersClient>> create(Config config);

    Status connect();
    void   disconnect();

    [[nodiscard]] bool is_connected() const;

    Status                     publish(const Channel& channel, ByteSpan data);
    Result<SubscriptionHandle> subscribe(const Channel& channel, MessageCallback callback);
    Status                     unsubscribe(SubscriptionHandle&& handle);

    Status                     drop(const DeadDropId& id, ByteSpan ciphertext);
    Result<DeadDropHandle>     watch(const DeadDropId& id, DeadDropCallback cb);
    Status                     unwatch(DeadDropHandle&& handle);
    Status                     retrieve(const DeadDropId& id, std::chrono::seconds ttl_hint, DeadDropCallback cb);

    void on_connected(std::function<void()> callback);
    void on_disconnected(std::function<void(Error)> callback);
    void on_error(std::function<void(Error)> callback);

    ShattersClient(const ShattersClient&) = delete;
    ShattersClient& operator=(const ShattersClient&) = delete;

private:
    ShattersClient();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}