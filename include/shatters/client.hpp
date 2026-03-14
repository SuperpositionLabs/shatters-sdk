#pragma once

#include <shatters/conversation/manager.hpp>
#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/identity/identity.hpp>
#include <shatters/messaging/subscription.hpp>
#include <shatters/storage/contact_store.hpp>
#include <shatters/types.hpp>
#include <shatters/x3dh/x3dh.hpp>

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


    [[nodiscard]] const identity::Identity& identity() const;
    [[nodiscard]] std::string address() const;


    Status add_contact(const std::string& address, const crypto::PublicKey& public_key, const std::string& display_name = {});
    Status remove_contact(const std::string& address);
    Result<std::vector<storage::ContactRecord>> list_contacts();


    Status send_message(const std::string& contact_address, ByteSpan plaintext);
    Status start_conversation(const std::string& contact_address, const x3dh::PreKeyBundle& their_bundle, ByteSpan first_message);

    Status upload_prekey_bundle(uint32_t num_one_time = 20);
    Result<x3dh::PreKeyBundle> fetch_bundle(const std::string& address, std::chrono::seconds timeout = std::chrono::seconds{5});

    Status resume_conversations();

    void on_message(conversation::IncomingCallback callback);

    
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