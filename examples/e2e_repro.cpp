// E2E reproducer for the two reported bugs:
//   Case 1: Alice has Bob; Bob does NOT have Alice. Alice sends. Bob should
//           auto-add Alice and receive the message. Then Bob manually adding
//           Alice must not crash.
//   Case 2: Alice and Bob have each other. Both call sendMessage from a fresh
//           login → both fall back to fetchBundle+startConversation. The first
//           message in each direction is reported missing in the UI; the
//           second one "fixes it".
//
// Run a relay on 127.0.0.1:4433 (with --config deploy/config.toml or
// allow_self_signed_tls=true) before launching this binary. Two SQLite DBs
// are written into a temp directory.
//
// Usage:  ./e2e_repro [--case1|--case2]   (default: both)

#include <shatters/client.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace shatters;
using namespace std::chrono_literals;

namespace fs = std::filesystem;

struct Inbox
{
    std::mutex mu;
    std::vector<std::pair<std::string, std::string>> msgs; // (from_addr, plaintext)
};

static void register_inbox(ShattersClient& c, Inbox& box, const std::string& tag)
{
    c.on_message([&box, tag](const conversation::DecryptedMessage& dm) {
        if (dm.outgoing) return;
        std::string pt(dm.plaintext.begin(), dm.plaintext.end());
        spdlog::info("[{}] RX from {}: \"{}\"", tag, dm.contact_address, pt);
        std::lock_guard lk(box.mu);
        box.msgs.emplace_back(dm.contact_address, std::move(pt));
    });
}

static std::unique_ptr<ShattersClient> make_client(const std::string& db_path,
                                                   const std::string& tag)
{
    ShattersClient::Config cfg;
    cfg.db_path        = db_path;
    cfg.db_pass        = "test-pass";
    cfg.server_host    = "127.0.0.1";
    cfg.server_port    = 4433;
    cfg.auto_reconnect = true;

    auto r = ShattersClient::create(std::move(cfg));
    if (r.is_err())
    {
        spdlog::error("[{}] create failed: {}", tag, r.error().message);
        return nullptr;
    }
    auto cl = std::move(r).take_value();

    auto cs = cl->connect();
    if (cs.is_err())
    {
        spdlog::error("[{}] connect failed: {}", tag, cs.error().message);
        return nullptr;
    }
    spdlog::info("[{}] connected as {}", tag, cl->address());
    return cl;
}

static void login_finish(ShattersClient& c, const std::string& tag)
{
    auto rs = c.resume_conversations();
    if (rs.is_err())
        spdlog::error("[{}] resume failed: {}", tag, rs.error().message);

    auto us = c.upload_prekey_bundle(20);
    if (us.is_err())
        spdlog::error("[{}] upload bundle failed: {}", tag, us.error().message);
}

static bool add_via_bundle(ShattersClient& me, const std::string& tag,
                           const std::string& peer_addr, const std::string& peer_label)
{
    auto bundle = me.fetch_bundle(peer_addr, 5s);
    if (bundle.is_err())
    {
        spdlog::error("[{}] fetch bundle({}) failed: {}", tag, peer_label, bundle.error().message);
        return false;
    }
    auto pk = bundle.value().identity_key;
    auto as = me.add_contact(peer_addr, pk, peer_label);
    if (as.is_err())
    {
        spdlog::error("[{}] add_contact failed: {}", tag, as.error().message);
        return false;
    }
    return true;
}

static bool send_with_bootstrap(ShattersClient& me, const std::string& tag,
                                const std::string& peer_addr, const std::string& text)
{
    Bytes pt(text.begin(), text.end());
    auto s1 = me.send_message(peer_addr, pt);
    if (s1.is_ok())
    {
        spdlog::info("[{}] sent (ratchet) → {}: \"{}\"", tag, peer_addr, text);
        return true;
    }
    spdlog::info("[{}] send failed ({}); bootstrapping", tag, s1.error().message);

    auto bundle = me.fetch_bundle(peer_addr, 5s);
    if (bundle.is_err())
    {
        spdlog::error("[{}] bootstrap fetch_bundle failed: {}", tag, bundle.error().message);
        return false;
    }
    auto s2 = me.start_conversation(peer_addr, bundle.value(), pt);
    if (s2.is_err())
    {
        spdlog::error("[{}] start_conversation failed: {}", tag, s2.error().message);
        return false;
    }
    spdlog::info("[{}] sent (X3DH) → {}: \"{}\"", tag, peer_addr, text);
    return true;
}

static size_t count_from(Inbox& box, const std::string& peer)
{
    std::lock_guard lk(box.mu);
    size_t n = 0;
    for (auto& m : box.msgs)
        if (m.first == peer) ++n;
    return n;
}

static bool wait_for(Inbox& box, const std::string& peer, size_t expected, std::chrono::milliseconds budget)
{
    auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (count_from(box, peer) >= expected) return true;
        std::this_thread::sleep_for(50ms);
    }
    return count_from(box, peer) >= expected;
}

static int run_case2(const std::string& tmp)
{
    spdlog::info("=== CASE 2: mutual contacts, dual fresh-login send ===");

    auto a_db = (fs::path(tmp) / "alice.db").string();
    auto b_db = (fs::path(tmp) / "bob.db").string();
    fs::remove(a_db);
    fs::remove(b_db);

    Inbox a_box, b_box;
    auto alice = make_client(a_db, "alice");
    auto bob   = make_client(b_db, "bob");
    if (!alice || !bob) return 1;

    register_inbox(*alice, a_box, "alice");
    register_inbox(*bob,   b_box, "bob");

    login_finish(*alice, "alice");
    login_finish(*bob,   "bob");

    auto a_addr = alice->address();
    auto b_addr = bob->address();

    // mutual add
    if (!add_via_bundle(*alice, "alice", b_addr, "Bob"))   return 2;
    if (!add_via_bundle(*bob,   "bob",   a_addr, "Alice")) return 2;

    // Alice sends first
    if (!send_with_bootstrap(*alice, "alice", b_addr, "Olá Bob")) return 3;

    // Bob sends roughly at the same time (no session yet on his side)
    std::this_thread::sleep_for(50ms);
    if (!send_with_bootstrap(*bob, "bob", a_addr, "Olá Alice")) return 3;

    bool got_b = wait_for(b_box, a_addr, 1, 3000ms);
    bool got_a = wait_for(a_box, b_addr, 1, 3000ms);

    spdlog::info("Bob got first from Alice? {}", got_b);
    spdlog::info("Alice got first from Bob? {}", got_a);

    // Now send a SECOND message via ratchet path
    std::this_thread::sleep_for(500ms);
    send_with_bootstrap(*alice, "alice", b_addr, "Segunda Alice→Bob");
    send_with_bootstrap(*bob,   "bob",   a_addr, "Segunda Bob→Alice");

    bool got_b2 = wait_for(b_box, a_addr, 2, 3000ms);
    bool got_a2 = wait_for(a_box, b_addr, 2, 3000ms);

    spdlog::info("Bob got second from Alice? {} (total={})", got_b2, count_from(b_box, a_addr));
    spdlog::info("Alice got second from Bob? {} (total={})", got_a2, count_from(a_box, b_addr));

    return (got_b && got_a && got_b2 && got_a2) ? 0 : 10;
}

static int run_case1(const std::string& tmp)
{
    spdlog::info("=== CASE 1: only Alice has Bob; Bob receives, then manually adds Alice ===");

    auto a_db = (fs::path(tmp) / "alice1.db").string();
    auto b_db = (fs::path(tmp) / "bob1.db").string();
    fs::remove(a_db);
    fs::remove(b_db);

    Inbox a_box, b_box;
    auto alice = make_client(a_db, "alice");
    auto bob   = make_client(b_db, "bob");
    if (!alice || !bob) return 1;

    register_inbox(*alice, a_box, "alice");
    register_inbox(*bob,   b_box, "bob");

    login_finish(*alice, "alice");
    login_finish(*bob,   "bob");

    auto a_addr = alice->address();
    auto b_addr = bob->address();

    // Only Alice adds Bob
    if (!add_via_bundle(*alice, "alice", b_addr, "Bob")) return 2;

    // Alice sends
    if (!send_with_bootstrap(*alice, "alice", b_addr, "Olá Bob (case1)")) return 3;

    bool got = wait_for(b_box, a_addr, 1, 3000ms);
    spdlog::info("Bob received first message via callback? {}", got);

    // Cross-check: did it land in message_store even if callback didn't fire?
    auto hist = bob->message_history(a_addr, 100);
    if (hist.is_ok())
        spdlog::info("Bob's message_store for alice has {} entries", hist.value().size());
    else
        spdlog::info("Bob's message_history error: {}", hist.error().message);

    // Verify Bob's contact list now contains Alice (auto-add)
    auto contacts = bob->list_contacts();
    bool has_alice_auto = false;
    if (contacts.is_ok())
        for (auto& c : contacts.value())
            if (c.address == a_addr) { has_alice_auto = true; break; }
    spdlog::info("Bob has Alice auto-added? {}", has_alice_auto);

    // Now Bob explicitly tries to add Alice (should be idempotent / not crash)
    auto bundle_a = bob->fetch_bundle(a_addr, 5s);
    if (bundle_a.is_err())
    {
        spdlog::error("[bob] fetch alice bundle: {}", bundle_a.error().message);
        return 4;
    }
    auto pk_a = bundle_a.value().identity_key;
    spdlog::info("[bob] calling add_contact(alice) explicitly...");
    auto add_s = bob->add_contact(a_addr, pk_a, "Alice");
    spdlog::info("[bob] add_contact result: {}", add_s.is_ok() ? "OK" : add_s.error().message);

    // Bob now sends back
    if (!send_with_bootstrap(*bob, "bob", a_addr, "Oi Alice (case1)")) return 5;
    bool got_a = wait_for(a_box, b_addr, 1, 3000ms);
    spdlog::info("Alice received Bob's reply? {}", got_a);

    return (got && has_alice_auto && add_s.is_ok() && got_a) ? 0 : 10;
}

int main(int argc, char** argv)
{
    spdlog::set_level(spdlog::level::debug);
    if (sodium_init() < 0) return 1;

    auto tmp = (fs::temp_directory_path() / "shatters_e2e_repro").string();
    fs::create_directories(tmp);

    bool only1 = false, only2 = false;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--case1") == 0) only1 = true;
        if (std::strcmp(argv[i], "--case2") == 0) only2 = true;
    }

    int rc1 = 0, rc2 = 0;
    if (!only2) rc1 = run_case1(tmp);
    if (!only1) rc2 = run_case2(tmp);

    spdlog::info("CASE1 exit={}  CASE2 exit={}", rc1, rc2);
    return (rc1 == 0 && rc2 == 0) ? 0 : 99;
}
