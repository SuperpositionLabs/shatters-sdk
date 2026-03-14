#include <shatters/conversation/manager.hpp>
#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/messaging/session.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>

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

    std::mutex                 mu;
    IncomingCallback           on_message_cb;

    std::unordered_map<std::string, ratchet::DoubleRatchet> ratchets;

    std::unordered_map<std::string, SubscriptionHandle> subscriptions;

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

        auto pt = it->second.decrypt(msg);
        if (pt.is_err())
        {
            spdlog::error("decrypt failed for {}: {}", addr, pt.error().message);
            return;
        }
              
        auto ps = persist_ratchet(addr);
        if (ps.is_err())
            spdlog::error("persist failed: {}", ps.error().message);

        auto new_ch = it->second.current_channel();
        auto ws = watch_channel(addr, new_ch);
        if (ws.is_err())
            spdlog::error("rewatch failed: {}", ws.error().message);

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

    auto spk = crypto::X25519KeyPair::generate();
    SHATTERS_TRY(spk);
    impl.signed_prekey = std::move(spk).take_value();

    return std::move(mgr);
}

Status Manager::send(const std::string& contact_address, ByteSpan plaintext)
{
    std::lock_guard lock(impl_->mu);

    SHATTERS_TRY(impl_->load_ratchet(contact_address));

    auto& dr = impl_->ratchets.at(contact_address);

    auto msg = dr.encrypt(plaintext);
    SHATTERS_TRY(msg);

    auto header_bytes = ratchet::serialize_header(msg.value().header);
    Bytes wire(header_bytes.size() + msg.value().ciphertext.size());
    std::memcpy(wire.data(), header_bytes.data(), header_bytes.size());
    std::memcpy(wire.data() + header_bytes.size(), msg.value().ciphertext.data(), msg.value().ciphertext.size());

    auto ch = dr.current_channel();
    auto ps = impl_->session->publish(ch, wire);
    SHATTERS_TRY(ps);

    SHATTERS_TRY(impl_->persist_ratchet(contact_address));

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    impl_->message_store->store(contact_address, 0, plaintext, now);

    return {};
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

    impl_->ratchets.emplace(contact_address, std::move(dr).take_value());
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

    auto ch = impl_->ratchets.at(contact_address).current_channel();
    SHATTERS_TRY(impl_->watch_channel(contact_address, ch));

    impl_->message_store->store(contact_address, 0, first_message, now);

    return {};
}

Status Manager::handle_initial_message(
    const x3dh::InitialMessage& initial_msg,
    ByteSpan                    ciphertext)
{
    std::lock_guard lock(impl_->mu);

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

    auto sender_addr = identity::ContactAddress::from_public_key(initial_msg.sender_identity_key);

    const auto& addr_str = sender_addr.to_string();
    impl_->ratchets.emplace(addr_str, std::move(dr).take_value());

    auto state_bytes = ratchet::serialize_state(impl_->ratchets.at(addr_str).state());
    auto sealed = impl_->db->encrypt_blob(state_bytes);
    SHATTERS_TRY(sealed);

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    storage::SessionRecord rec
    {
        .contact_address = addr_str,
        .encrypted_state = std::move(sealed).take_value(),
        .updated_at      = now,
    };
    SHATTERS_TRY(impl_->session_store->store(rec));

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

    auto ch = impl_->ratchets.at(addr_str).current_channel();
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

        auto ch = impl_->ratchets.at(addr).current_channel();
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
        bundle.one_time_prekeys.push_back(r.public_key);

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