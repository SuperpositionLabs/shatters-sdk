#include <shatters/conversation/manager.hpp>
#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/messaging/session.hpp>

#include <sqlite3.h>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace shatters::conversation
{

struct Manager::Impl
{
    identity::Identity*        identity{};
    Session*                   session{};

    storage::Database*         db{};
    storage::SessionStore*     session_store{};
    storage::ContactStore*     contact_store{};
    storage::MessageStore*     message_store{};
    storage::PreKeyStore*      prekey_store{};

    std::optional<crypto::X25519KeyPair> signed_prekey;

    std::recursive_mutex       mu;
    IncomingCallback           on_message_cb;

    std::unordered_map<std::string, ratchet::DoubleRatchet> ratchets;

    std::unordered_map<std::string, SubscriptionHandle> subscriptions;

    std::optional<SubscriptionHandle> intro_subscription;

    // Tracks contacts for which initiate_session() was called in this run.
    // Used to distinguish real-time dual-initiation from stale deaddrop replays.
    std::unordered_set<std::string> initiated_this_session;

    Status load_ratchet(const std::string& addr)
    {
        if (ratchets.contains(addr))
            return {};

        auto rec = session_store->find(addr);
        SHATTERS_TRY(rec);
        if (!rec.value().has_value())
            return Error{ErrorCode::InternalError, "no session for " + addr};

        auto dec = db->decrypt_blob(rec.value()->encrypted_state);
        SHATTERS_TRY(dec);

        auto state = ratchet::deserialize_state(dec.value());
        SHATTERS_TRY(state);

        auto dr = ratchet::DoubleRatchet::from_state(std::move(state).take_value());
        SHATTERS_TRY(dr);

        ratchets.emplace(addr, std::move(dr).take_value());
        return {};
    }

    Status persist_ratchet(const std::string& addr)
    {
        auto it = ratchets.find(addr);
        if (it == ratchets.end())
            return Error{ErrorCode::InternalError, "ratchet not loaded"};

        auto state_bytes = ratchet::serialize_state(it->second.state());
        auto sealed = db->encrypt_blob(state_bytes);
        SHATTERS_TRY(sealed);

        storage::SessionRecord rec
        {
            .contact_address = addr,
            .encrypted_state = std::move(sealed).take_value(),
            .updated_at = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count(),
        };
        return session_store->update(rec);
    }

    Channel conv_channel(const std::string& remote_addr) const
    {
        auto my_addr = identity->address().to_string();
        const auto& a = (my_addr < remote_addr) ? my_addr : remote_addr;
        const auto& b = (my_addr < remote_addr) ? remote_addr : my_addr;

        unsigned char hash[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_state st;
        static constexpr unsigned char zero_key[32] = {};
        crypto_auth_hmacsha256_init(&st, zero_key, sizeof(zero_key));
        crypto_auth_hmacsha256_update(&st,
            reinterpret_cast<const unsigned char*>("shatters-conversation"), 21);
        crypto_auth_hmacsha256_update(&st,
            reinterpret_cast<const unsigned char*>(a.data()), a.size());
        crypto_auth_hmacsha256_update(&st,
            reinterpret_cast<const unsigned char*>(b.data()), b.size());
        crypto_auth_hmacsha256_final(&st, hash);

        Channel ch{};
        std::memcpy(ch.data(), hash, CHANNEL_SIZE);
        return ch;
    }

    Status watch_channel(const std::string& addr, const Channel& channel)
    {
        subscriptions.erase(addr);

        auto handle = session->subscribe(channel,
            [this, addr](const Channel&, ByteSpan data)
            {
                on_incoming(addr, data);
            });
        SHATTERS_TRY(handle);

        subscriptions.emplace(addr, std::move(handle).take_value());
        return {};
    }

    void on_incoming(const std::string& addr, ByteSpan data)
    {
        std::lock_guard lock(mu);

        if (data.size() < ratchet::RATCHET_HEADER_SIZE)
        {
            spdlog::warn("short ratchet message from {}", addr);
            return;
        }

        auto header_r = ratchet::deserialize_header(data.subspan(0, ratchet::RATCHET_HEADER_SIZE));
        if (header_r.is_err()) return;

        ratchet::RatchetMessage msg{
            .header = header_r.value(),
            .ciphertext = Bytes(
                data.begin() + ratchet::RATCHET_HEADER_SIZE,
                data.end()),
        };

        auto it = ratchets.find(addr);
        if (it == ratchets.end())
        {
            spdlog::warn("no ratchet for {}", addr);
            return;
        }

        if (msg.header.dh_public == it->second.state().dh_self_public)
            return;

        auto pt = it->second.decrypt(msg);
        if (pt.is_err())
        {
            spdlog::error("decrypt failed for {}: {}", addr, pt.error().message);
            return;
        }

        auto ps = persist_ratchet(addr);
        if (ps.is_err())
            spdlog::error("persist failed: {}", ps.error().message);

        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        message_store->store(addr, 1, pt.value(), now);

        if (on_message_cb)
        {
            DecryptedMessage dm
            {
                .contact_address = addr,
                .plaintext       = std::move(pt).take_value(),
                .timestamp_ms    = now,
                .outgoing        = false,
            };
            on_message_cb(dm);
        }
    }
};

Manager::Manager() : impl_(std::make_unique<Impl>()) {}
Manager::~Manager() = default;

Result<std::unique_ptr<Manager>> Manager::create(
    identity::Identity&        identity,
    Session&                   session,
    storage::Database&         db,
    storage::SessionStore&     session_store,
    storage::ContactStore&     contact_store,
    storage::MessageStore&     message_store,
    storage::PreKeyStore&      prekey_store)
{
    auto mgr = std::unique_ptr<Manager>(new Manager());
    auto& impl = *mgr->impl_;

    impl.identity      = &identity;
    impl.session        = &session;
    impl.db             = &db;
    impl.session_store  = &session_store;
    impl.contact_store  = &contact_store;
    impl.message_store  = &message_store;
    impl.prekey_store   = &prekey_store;

    bool spk_loaded = false;
    auto* sqlite_db = static_cast<sqlite3*>(db.raw_handle());
    {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(sqlite_db,
            "SELECT value FROM metadata WHERE key = 'signed_prekey'",
            -1, &stmt, nullptr
        );
        if (rc == SQLITE_OK)
        {
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const void* blob = sqlite3_column_blob(stmt, 0);
                int blob_len = sqlite3_column_bytes(stmt, 0);
                if (blob && blob_len > 0)
                {
                    auto dec = db.decrypt_blob(
                        ByteSpan(static_cast<const uint8_t*>(blob),
                                 static_cast<size_t>(blob_len)));
                    if (dec.is_ok() && dec.value().size() == crypto::X25519_KEY_SIZE)
                    {
                        auto kp = crypto::X25519KeyPair::from_secret(dec.value());
                        if (kp.is_ok())
                        {
                            impl.signed_prekey = std::move(kp).take_value();
                            spk_loaded = true;
                        }
                    }
                }
            }
            sqlite3_finalize(stmt);
        }
    }

    if (!spk_loaded)
    {
        auto spk = crypto::X25519KeyPair::generate();
        SHATTERS_TRY(spk);
        impl.signed_prekey = std::move(spk).take_value();

        auto sealed = db.encrypt_blob(impl.signed_prekey->secret_key().span());
        if (sealed.is_ok())
        {
            sqlite3_stmt* stmt = nullptr;
            int rc = sqlite3_prepare_v2(sqlite_db,
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('signed_prekey', ?)",
                -1, &stmt, nullptr);
            if (rc == SQLITE_OK)
            {
                sqlite3_bind_blob(stmt, 1,
                    sealed.value().data(),
                    static_cast<int>(sealed.value().size()),
                    SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }

    return std::move(mgr);
}

Status Manager::send(const std::string& contact_address, ByteSpan plaintext)
{
    std::lock_guard lock(impl_->mu);

    SHATTERS_TRY(impl_->load_ratchet(contact_address));

    auto& dr = impl_->ratchets.at(contact_address);

    auto state_snapshot = dr.state();

    auto msg = dr.encrypt(plaintext);
    SHATTERS_TRY(msg);

    auto header_bytes = ratchet::serialize_header(msg.value().header);
    Bytes wire(header_bytes.size() + msg.value().ciphertext.size());
    std::memcpy(wire.data(), header_bytes.data(), header_bytes.size());
    std::memcpy(wire.data() + header_bytes.size(), msg.value().ciphertext.data(), msg.value().ciphertext.size());

    auto ch = impl_->conv_channel(contact_address);
    auto ps = impl_->session->publish(ch, wire);
    if (ps.is_err())
    {
        auto rollback = ratchet::DoubleRatchet::from_state(std::move(state_snapshot));
        if (rollback.is_ok())
            dr = std::move(rollback).take_value();
        return ps.error();
    }

    auto persist_status = impl_->persist_ratchet(contact_address);
    if (persist_status.is_err())
    {
        auto rollback = ratchet::DoubleRatchet::from_state(std::move(state_snapshot));
        if (rollback.is_ok())
            dr = std::move(rollback).take_value();
        return persist_status.error();
    }

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    impl_->message_store->store(contact_address, 0, plaintext, now);

    return {};
}

Result<std::vector<HistoryMessage>>
Manager::history(
    const std::string& contact_address,
    size_t limit,
    size_t offset)
{
    std::lock_guard lock(impl_->mu);

    auto records_r = impl_->message_store->list (contact_address, limit, offset);
    SHATTERS_TRY(records_r);

    std::vector<HistoryMessage> out;
    out.reserve(records_r.value().size());

    for (const auto& rec : records_r.value())
    {
        auto pt = impl_->db->decrypt_blob(rec.encrypted_content);
        if (pt.is_err())
            continue;

        HistoryMessage hm;
        hm.id = rec.id;
        hm.contact_address = rec.contact_address;
        hm.plaintext = std::move(pt).take_value();
        hm.timestamp_ms = rec.timestamp_ms;
        hm.outgoing = (rec.direction == 0);

        out.push_back(std::move(hm));
    }
    return out;
}

Status Manager::initiate_session(
    const std::string&          contact_address,
    const x3dh::PreKeyBundle&   their_bundle,
    ByteSpan                    first_message)
{
    std::lock_guard lock(impl_->mu);

    auto x3dh_r = x3dh::initiate(impl_->identity->keypair(), their_bundle);
    SHATTERS_TRY(x3dh_r);

    auto dr = ratchet::DoubleRatchet::init_initiator(x3dh_r.value().shared_secret, their_bundle.signed_prekey);
    SHATTERS_TRY(dr);

    auto ct = dr.value().encrypt(first_message);
    SHATTERS_TRY(ct);

    auto ratchet_header = ratchet::serialize_header(ct.value().header);
    Bytes ratchet_wire(ratchet_header.size() + ct.value().ciphertext.size());
    std::memcpy(ratchet_wire.data(), ratchet_header.data(), ratchet_header.size());
    std::memcpy(ratchet_wire.data() + ratchet_header.size(), ct.value().ciphertext.data(), ct.value().ciphertext.size());

    x3dh::InitialMessage initial
    {
        .sender_identity_key = impl_->identity->public_key(),
        .ephemeral_key       = x3dh_r.value().ephemeral_public,
        .opk_id              = x3dh_r.value().opk_id,
        .ciphertext          = std::move(ratchet_wire),
    };
    auto initial_wire = x3dh::serialize_initial(initial);

    auto their_addr = identity::ContactAddress::from_string(contact_address);
    SHATTERS_TRY(their_addr);
    auto intro_ch = their_addr.value().intro_channel();

    auto ps = impl_->session->publish(intro_ch, initial_wire);
    SHATTERS_TRY(ps);

    impl_->ratchets.insert_or_assign(contact_address, std::move(dr).take_value());
    impl_->initiated_this_session.insert(contact_address);
    SHATTERS_TRY(impl_->persist_ratchet(contact_address));

    auto state_bytes = ratchet::serialize_state(impl_->ratchets.at(contact_address).state());
    auto sealed = impl_->db->encrypt_blob(state_bytes);
    SHATTERS_TRY(sealed);

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    storage::SessionRecord rec
    {
        .contact_address = contact_address,
        .encrypted_state = std::move(sealed).take_value(),
        .updated_at      = now,
    };
    SHATTERS_TRY(impl_->session_store->store(rec));

    auto ch = impl_->conv_channel(contact_address);
    SHATTERS_TRY(impl_->watch_channel(contact_address, ch));

    impl_->message_store->store(contact_address, 0, first_message, now);

    return {};
}

Status Manager::handle_initial_message(
    const x3dh::InitialMessage& initial_msg,
    ByteSpan                    ciphertext)
{
    std::lock_guard lock(impl_->mu);

    auto sender_addr = identity::ContactAddress::from_public_key(initial_msg.sender_identity_key);
    const auto& addr_str = sender_addr.to_string();

    if (impl_->ratchets.contains(addr_str))
    {
        if (!impl_->initiated_this_session.contains(addr_str))
        {
            // Session loaded from DB on restart — stale deaddrop replay, ignore
            spdlog::info("ignoring stale InitialMessage from {} (session already established)", addr_str);
            return {};
        }

        // Genuine dual-initiation: both peers initiated in this session
        auto my_addr = impl_->identity->address().to_string();
        if (my_addr < addr_str)
        {
            spdlog::info("dual-initiation: keeping ours (we < {})", addr_str);
            return {};
        }

        spdlog::info("dual-initiation: accepting theirs ({} < us)", addr_str);
    }

    const crypto::X25519KeyPair* opk_ptr = nullptr;
    std::optional<crypto::X25519KeyPair> opk_kp;

    if (initial_msg.opk_id != x3dh::NO_OPK)
    {
        auto rec = impl_->prekey_store->find(initial_msg.opk_id);
        SHATTERS_TRY(rec);
        if (rec.value().has_value())
        {
            auto kp = impl_->prekey_store->decrypt(rec.value().value());
            SHATTERS_TRY(kp);

            opk_kp = std::move(kp).take_value();
            opk_ptr = &opk_kp.value();
            impl_->prekey_store->mark_used(initial_msg.opk_id);
        }
    }

    auto sk = x3dh::respond(
        impl_->identity->keypair(),
        *impl_->signed_prekey,
        opk_ptr,
        initial_msg.sender_identity_key,
        initial_msg.ephemeral_key
    );
    SHATTERS_TRY(sk);

    auto dr = ratchet::DoubleRatchet::init_responder(sk.value(), *impl_->signed_prekey);
    SHATTERS_TRY(dr);

    if (ciphertext.size() < ratchet::RATCHET_HEADER_SIZE)
        return Error{ErrorCode::ProtocolError, "initial message payload too short"};

    auto hdr = ratchet::deserialize_header(ciphertext.subspan(0, ratchet::RATCHET_HEADER_SIZE));
    SHATTERS_TRY(hdr);

    ratchet::RatchetMessage rm
    {
        .header = hdr.value(),
        .ciphertext = Bytes(
            ciphertext.begin() + ratchet::RATCHET_HEADER_SIZE,
            ciphertext.end()
        ),
    };

    auto pt = dr.value().decrypt(rm);
    SHATTERS_TRY(pt);

    impl_->ratchets.insert_or_assign(addr_str, std::move(dr).take_value());

    auto state_bytes = ratchet::serialize_state(impl_->ratchets.at(addr_str).state());
    auto sealed = impl_->db->encrypt_blob(state_bytes);
    SHATTERS_TRY(sealed);

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    auto existing = impl_->contact_store->find(addr_str);
    if (existing.is_ok() && !existing.value().has_value())
    {
        storage::ContactRecord cr
        {
            .address      = addr_str,
            .public_key   = initial_msg.sender_identity_key,
            .display_name = {},
            .added_at     = now,
        };
        impl_->contact_store->store(cr);
    }

    storage::SessionRecord rec
    {
        .contact_address = addr_str,
        .encrypted_state = std::move(sealed).take_value(),
        .updated_at      = now,
    };
    SHATTERS_TRY(impl_->session_store->store(rec));

    auto ch = impl_->conv_channel(addr_str);
    SHATTERS_TRY(impl_->watch_channel(addr_str, ch));

    impl_->message_store->store(addr_str, 1, pt.value(), now);

    if (impl_->on_message_cb)
    {
        DecryptedMessage dm
        {
            .contact_address = addr_str,
            .plaintext       = std::move(pt).take_value(),
            .timestamp_ms    = now,
            .outgoing        = false,
        };
        impl_->on_message_cb(dm);
    }

    return {};
}

Status Manager::resume_all()
{
    std::lock_guard lock(impl_->mu);

    auto addrs = impl_->session_store->list_active();
    SHATTERS_TRY(addrs);

    for (const auto& addr : addrs.value())
    {
        auto ls = impl_->load_ratchet(addr);
        if (ls.is_err())
        {
            spdlog::warn("skip session {}: {}", addr, ls.error().message);
            continue;
        }

        auto ch = impl_->conv_channel(addr);
        auto ws = impl_->watch_channel(addr, ch);
        if (ws.is_err())
            spdlog::warn("watch failed for {}: {}", addr, ws.error().message);
    }

    auto intro_ch = impl_->identity->address().intro_channel();
    auto handle = impl_->session->subscribe(intro_ch,
        [this](const Channel&, ByteSpan data)
        {
            auto im = x3dh::deserialize_initial(data);
            if (im.is_err())
                return;

            auto status = handle_initial_message(
                im.value(),
                im.value().ciphertext
            );
            if (status.is_err())
                spdlog::error("handle initial: {}", status.error().message);
        });
    SHATTERS_TRY(handle);

    impl_->intro_subscription = std::move(handle).take_value();

    // Retrieve offline messages from the deaddrop for conversation channels only.
    // The intro channel is NOT retrieved: stale InitialMessages would replay
    // X3DH with consumed OPKs, corrupting established sessions.
    constexpr uint32_t ttl_val = 86400;
    uint8_t ttl_buf[4] = {
        static_cast<uint8_t>((ttl_val >> 24) & 0xFF),
        static_cast<uint8_t>((ttl_val >> 16) & 0xFF),
        static_cast<uint8_t>((ttl_val >>  8) & 0xFF),
        static_cast<uint8_t>((ttl_val      ) & 0xFF),
    };
    ByteSpan ttl_span(ttl_buf, 4);

    for (const auto& addr : addrs.value())
    {
        auto ch = impl_->conv_channel(addr);
        impl_->session->retrieve(ch, ttl_span);
    }

    return {};
}

Status Manager::upload_bundle(uint32_t num_one_time)
{
    std::lock_guard lock(impl_->mu);

    auto existing = impl_->prekey_store->list_unused();
    SHATTERS_TRY(existing);

    auto next_id_r = impl_->prekey_store->next_id();
    SHATTERS_TRY(next_id_r);
    auto next_id = next_id_r.value();

    const auto existing_count = static_cast<uint32_t>(existing.value().size());
    const auto to_generate = (num_one_time > existing_count) ? num_one_time - existing_count : 0u;

    for (uint32_t i = 0; i < to_generate; ++i)
    {
        auto kp = crypto::X25519KeyPair::generate();
        SHATTERS_TRY(kp);
        SHATTERS_TRY(impl_->prekey_store->store(next_id + i, kp.value()));
    }

    auto all_opks = impl_->prekey_store->list_unused();
    SHATTERS_TRY(all_opks);

    x3dh::PreKeyBundle bundle
    {
        .identity_key     = impl_->identity->public_key(),
        .signed_prekey    = impl_->signed_prekey->public_key(),
        .signed_prekey_sig = {},
        .one_time_prekeys  = {},
    };

    auto sig = impl_->identity->keypair().sign(impl_->signed_prekey->public_key());
    SHATTERS_TRY(sig);
    bundle.signed_prekey_sig = sig.value();

    for (const auto& r : all_opks.value())
        bundle.one_time_prekeys.push_back({r.id, r.public_key});

    auto wire = x3dh::serialize_bundle(bundle);

    auto intro_ch = impl_->identity->address().intro_channel();

    impl_->session->upload_bundle(intro_ch, wire);

    return {};
}

void Manager::on_message(IncomingCallback callback)
{
    std::lock_guard lock(impl_->mu);
    impl_->on_message_cb = std::move(callback);
}

const crypto::X25519KeyPair& Manager::signed_prekey() const
{
    return *impl_->signed_prekey;
}

}
