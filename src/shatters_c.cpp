/**
 * @file shatters_c.cpp
 * @brief extern "C" wrapper around ShattersClient for FFI consumption.
 */

#include <shatters/shatters_c.h>

#include <shatters/client.hpp>
#include <shatters/x3dh/x3dh.hpp>

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>

/* ---------- helpers ---------- */

namespace
{

ShattersErrorCode map_code(shatters::ErrorCode c)
{
    return static_cast<ShattersErrorCode>(static_cast<uint8_t>(c));
}

ShattersStatus ok_status()
{
    return ShattersStatus{SHATTERS_OK, nullptr};
}

ShattersStatus err_status(const shatters::Error& e)
{
    char* msg = nullptr;
    if (!e.message.empty())
    {
        msg = static_cast<char*>(std::malloc(e.message.size() + 1));
        if (msg)
        {
            std::memcpy(msg, e.message.c_str(), e.message.size() + 1);
        }
    }
    return ShattersStatus{map_code(e.code), msg};
}

char* dup_string(const std::string& s)
{
    auto* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (p)
        std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

}

/* ---------- lifecycle ---------- */

ShattersStatus shatters_create(
    const char* db_path,
    const char* db_pass,
    const char* server_host,
    uint16_t    server_port,
    const uint8_t* tls_pin, size_t tls_pin_len,
    int auto_reconnect,
    ShattersClient** out)
{
    if (!out)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("out is null")};

    shatters::ShattersClient::Config cfg;
    cfg.db_path        = db_path  ? db_path  : "";
    cfg.db_pass        = db_pass  ? db_pass  : "";
    cfg.server_host    = server_host ? server_host : "";
    cfg.server_port    = server_port;
    cfg.auto_reconnect = auto_reconnect != 0;

    if (tls_pin && tls_pin_len > 0)
        cfg.tls_pin_sha256.assign(tls_pin, tls_pin + tls_pin_len);

    auto result = shatters::ShattersClient::create(std::move(cfg));
    if (result.is_err())
        return err_status(result.error());

    *out = reinterpret_cast<ShattersClient*>(std::move(result).take_value().release());
    return ok_status();
}

void shatters_destroy(ShattersClient* client)
{
    delete reinterpret_cast<shatters::ShattersClient*>(client);
}

/* ---------- connection ---------- */

ShattersStatus shatters_connect(ShattersClient* client)
{
    if (!client)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("client is null")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->connect();
    return s.is_ok() ? ok_status() : err_status(s.error());
}

void shatters_disconnect(ShattersClient* client)
{
    if (client)
        reinterpret_cast<shatters::ShattersClient*>(client)->disconnect();
}

int shatters_is_connected(const ShattersClient* client)
{
    if (!client) return 0;
    return reinterpret_cast<const shatters::ShattersClient*>(client)->is_connected() ? 1 : 0;
}

/* ---------- identity ---------- */

char* shatters_address(const ShattersClient* client)
{
    if (!client) return nullptr;
    auto* c = reinterpret_cast<const shatters::ShattersClient*>(client);
    return dup_string(c->address());
}

ShattersStatus shatters_public_key(const ShattersClient* client, uint8_t out_pk[32])
{
    if (!client || !out_pk)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto* c  = reinterpret_cast<const shatters::ShattersClient*>(client);
    auto& pk = c->identity().keypair().ed25519_public();
    std::memcpy(out_pk, pk.data(), 32);
    return ok_status();
}

/* ---------- messaging ---------- */

ShattersStatus shatters_send_message(
    ShattersClient* client,
    const char* contact_address,
    const uint8_t* plaintext, size_t plaintext_len)
{
    if (!client || !contact_address || (!plaintext && plaintext_len > 0))
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->send_message(contact_address, {plaintext, plaintext_len});
    return s.is_ok() ? ok_status() : err_status(s.error());
}

ShattersStatus shatters_message_history(
    ShattersClient* client,
    const char* contact_address,
    size_t limit,
    size_t offset,
    ShattersHistoryList* out)
{
    if (!client || !contact_address || !out)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto r  = c->message_history(contact_address, limit, offset);
    if (r.is_err())
        return err_status(r.error());

    auto& msgs = r.value();
    out->count = msgs.size();
    out->items = nullptr;

    if (!msgs.empty())
    {
        out->items = static_cast<ShattersHistoryMessage*>(
            std::calloc(msgs.size(), sizeof(ShattersHistoryMessage)));
        if (!out->items)
            return ShattersStatus{SHATTERS_ERR_INTERNAL, dup_string("allocation failed")};

        for (size_t i = 0; i < msgs.size(); ++i)
        {
            auto& src = msgs[i];
            auto& dst = out->items[i];

            dst.id              = src.id;
            dst.contact_address = dup_string(src.contact_address);
            dst.timestamp_ms    = src.timestamp_ms;
            dst.outgoing        = src.outgoing ? 1 : 0;
            dst.plaintext_len   = src.plaintext.size();

            if (!src.plaintext.empty())
            {
                dst.plaintext = static_cast<uint8_t*>(std::malloc(src.plaintext.size()));
                if (dst.plaintext)
                    std::memcpy(dst.plaintext, src.plaintext.data(), src.plaintext.size());
            }
        }
    }
    return ok_status();
}

ShattersStatus shatters_upload_prekey_bundle(ShattersClient* client, uint32_t num_one_time)
{
    if (!client)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("client is null")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->upload_prekey_bundle(num_one_time);
    return s.is_ok() ? ok_status() : err_status(s.error());
}

ShattersStatus shatters_resume_conversations(ShattersClient* client)
{
    if (!client)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("client is null")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->resume_conversations();
    return s.is_ok() ? ok_status() : err_status(s.error());
}

/* ---------- contacts ---------- */

ShattersStatus shatters_add_contact(
    ShattersClient* client,
    const char* address,
    const uint8_t public_key[32],
    const char* display_name)
{
    if (!client || !address || !public_key)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    shatters::crypto::PublicKey pk{};
    std::memcpy(pk.data(), public_key, 32);

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->add_contact(address, pk, display_name ? display_name : "");
    return s.is_ok() ? ok_status() : err_status(s.error());
}

ShattersStatus shatters_remove_contact(ShattersClient* client, const char* address)
{
    if (!client || !address)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->remove_contact(address);
    return s.is_ok() ? ok_status() : err_status(s.error());
}

ShattersStatus shatters_list_contacts(ShattersClient* client, ShattersContactList* out)
{
    if (!client || !out)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto r  = c->list_contacts();
    if (r.is_err())
        return err_status(r.error());

    auto& contacts = r.value();
    out->count = contacts.size();
    out->items = nullptr;

    if (!contacts.empty())
    {
        out->items = static_cast<ShattersContact*>(
            std::calloc(contacts.size(), sizeof(ShattersContact)));
        if (!out->items)
            return ShattersStatus{SHATTERS_ERR_INTERNAL, dup_string("allocation failed")};

        for (size_t i = 0; i < contacts.size(); ++i)
        {
            auto& src = contacts[i];
            auto& dst = out->items[i];

            dst.address      = dup_string(src.address);
            dst.display_name = dup_string(src.display_name);
            dst.added_at     = src.added_at;
            std::memcpy(dst.public_key, src.public_key.data(), 32);
        }
    }
    return ok_status();
}

/* ---------- callbacks ---------- */

void shatters_on_connected(ShattersClient* client, ShattersOnConnected cb, void* ctx)
{
    if (!client) return;
    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    c->on_connected([cb, ctx]() { if (cb) cb(ctx); });
}

void shatters_on_disconnected(ShattersClient* client, ShattersOnDisconnected cb, void* ctx)
{
    if (!client) return;
    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    c->on_disconnected([cb, ctx](shatters::Error e)
    {
        if (cb)
            cb(ctx, map_code(e.code), e.message.c_str());
    });
}

void shatters_on_error(ShattersClient* client, ShattersOnError cb, void* ctx)
{
    if (!client) return;
    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    c->on_error([cb, ctx](shatters::Error e)
    {
        if (cb)
            cb(ctx, map_code(e.code), e.message.c_str());
    });
}

void shatters_on_message(ShattersClient* client, ShattersOnMessage cb, void* ctx)
{
    if (!client) return;
    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    c->on_message([cb, ctx](const shatters::conversation::DecryptedMessage& msg)
    {
        if (cb)
            cb(ctx, msg.contact_address.c_str(),
               msg.plaintext.data(), msg.plaintext.size(),
               msg.timestamp_ms, msg.outgoing ? 1 : 0);
    });
}

/* ---------- key exchange ---------- */

ShattersStatus shatters_start_conversation(
    ShattersClient* client,
    const char* contact_address,
    const uint8_t* bundle_data, size_t bundle_len,
    const uint8_t* first_message, size_t first_message_len)
{
    if (!client || !contact_address || !bundle_data)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto bundle = shatters::x3dh::deserialize_bundle({bundle_data, bundle_len});
    if (bundle.is_err())
        return err_status(bundle.error());

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto s  = c->start_conversation(
        contact_address,
        bundle.value(),
        {first_message, first_message_len});

    return s.is_ok() ? ok_status() : err_status(s.error());
}

ShattersStatus shatters_fetch_bundle(
    ShattersClient* client,
    const char* address,
    uint32_t timeout_secs,
    ShattersBytes* out)
{
    if (!client || !address || !out)
        return ShattersStatus{SHATTERS_ERR_INVALID_ARG, dup_string("null argument")};

    auto* c = reinterpret_cast<shatters::ShattersClient*>(client);
    auto r  = c->fetch_bundle(address, std::chrono::seconds{timeout_secs});
    if (r.is_err())
        return err_status(r.error());

    auto bundle_bytes = shatters::x3dh::serialize_bundle(std::move(r).take_value());
    out->len  = bundle_bytes.size();
    out->data = nullptr;

    if (!bundle_bytes.empty())
    {
        out->data = static_cast<uint8_t*>(std::malloc(bundle_bytes.size()));
        if (out->data)
            std::memcpy(out->data, bundle_bytes.data(), bundle_bytes.size());
    }
    return ok_status();
}

/* ---------- free helpers ---------- */

void shatters_string_free(char* s)
{
    std::free(s);
}

void shatters_bytes_free(ShattersBytes* buf)
{
    if (buf)
    {
        std::free(buf->data);
        buf->data = nullptr;
        buf->len  = 0;
    }
}

void shatters_contact_list_free(ShattersContactList* list)
{
    if (!list) return;
    for (size_t i = 0; i < list->count; ++i)
    {
        std::free(list->items[i].address);
        std::free(list->items[i].display_name);
    }
    std::free(list->items);
    list->items = nullptr;
    list->count = 0;
}

void shatters_history_list_free(ShattersHistoryList* list)
{
    if (!list) return;
    for (size_t i = 0; i < list->count; ++i)
    {
        std::free(list->items[i].contact_address);
        std::free(list->items[i].plaintext);
    }
    std::free(list->items);
    list->items = nullptr;
    list->count = 0;
}

void shatters_status_free(ShattersStatus* status)
{
    if (status)
    {
        std::free(status->message);
        status->message = nullptr;
    }
}
