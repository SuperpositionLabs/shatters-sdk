#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/identity/address.hpp>
#include <shatters/identity/identity.hpp>
#include <shatters/ratchet/double_ratchet.hpp>
#include <shatters/storage/contact_store.hpp>
#include <shatters/storage/message_store.hpp>
#include <shatters/storage/prekey_store.hpp>
#include <shatters/storage/session_store.hpp>
#include <shatters/x3dh/x3dh.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace shatters
{

class Session;

namespace conversation
{

struct DecryptedMessage
{
    std::string contact_address;
    Bytes       plaintext;
    int64_t     timestamp_ms;
    bool        outgoing;
};

using IncomingCallback = std::function<void(const DecryptedMessage&)>;

class Manager
{
public:
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    static Result<std::unique_ptr<Manager>> create(
        identity::Identity&        identity,
        Session&                   session,
        storage::Database&         db,
        storage::SessionStore&     session_store,
        storage::ContactStore&     contact_store,
        storage::MessageStore&     message_store,
        storage::PreKeyStore&      prekey_store);

    Status send(const std::string& contact_address, ByteSpan plaintext);

    Status initiate_session(
        const std::string&          contact_address,
        const x3dh::PreKeyBundle&   their_bundle,
        ByteSpan                    first_message);

    Status handle_initial_message(
        const x3dh::InitialMessage& initial_msg,
        ByteSpan                    ciphertext);

    Status resume_all();

    Status upload_bundle(uint32_t num_one_time = 20);

    void on_message(IncomingCallback callback);

    [[nodiscard]] const crypto::X25519KeyPair& signed_prekey() const;

private:
    Manager();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
}