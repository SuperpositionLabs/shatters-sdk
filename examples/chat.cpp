#include <shatters/client.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstring>
#include <csignal>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

static std::atomic<bool> g_running{true};
static void on_signal(int) { g_running.store(false); }

static std::mutex g_io;

static void print(const std::string& s)
{
    std::lock_guard lk(g_io);
    std::cout << s << std::flush;
}

static void println(const std::string& s)
{
    print(s + "\n");
}

static std::string to_hex(const uint8_t* data, size_t len)
{
    std::string out(len * 2, '\0');
    sodium_bin2hex(out.data(), out.size() + 1, data, len);
    return out;
}

static bool from_hex(const std::string& hex, uint8_t* out, size_t out_len)
{
    if (hex.size() != out_len * 2) return false;
    size_t bin_len = 0;
    return sodium_hex2bin(
        out, out_len, hex.c_str(), hex.size(),nullptr, &bin_len, nullptr
    ) == 0 && bin_len == out_len;
}

static shatters::Channel derive_inbox(const shatters::crypto::PublicKey& pk)
{
    shatters::Channel ch{};
    static constexpr unsigned char ctx[] = "inbox";
    crypto_generichash(ch.data(), ch.size(), pk.data(), pk.size(), ctx, sizeof(ctx) - 1);
    return ch;
}

static shatters::Bytes seal_encrypt(shatters::ByteSpan plaintext, const shatters::crypto::X25519Public& recipient_pk)
{
    shatters::Bytes ct(plaintext.size() + crypto_box_SEALBYTES);
    crypto_box_seal(ct.data(), plaintext.data(), plaintext.size(), recipient_pk.data());
    return ct;
}

static shatters::Result<shatters::Bytes> seal_decrypt(
    shatters::ByteSpan ciphertext,
    const shatters::crypto::X25519Public& our_pk,
    const shatters::crypto::X25519Secret& our_sk)
{
    if (ciphertext.size() < crypto_box_SEALBYTES)
        return shatters::Error{shatters::ErrorCode::CryptoError, "ciphertext too short"};

    shatters::Bytes pt(ciphertext.size() - crypto_box_SEALBYTES);
    if (crypto_box_seal_open(pt.data(), ciphertext.data(), ciphertext.size(), our_pk.data(), our_sk.data()) != 0)
        return shatters::Error{shatters::ErrorCode::CryptoError, "decryption failed"};

    return pt;
}

static shatters::Bytes build_payload(
    const shatters::crypto::IdentityKeyPair& kp,
    const std::string& text)
{
    const auto& sender_pk = kp.ed25519_public();

    shatters::Bytes to_sign(32 + text.size());
    std::memcpy(to_sign.data(), sender_pk.data(), 32);
    std::memcpy(to_sign.data() + 32, text.data(), text.size());

    auto sig = kp.sign(shatters::ByteSpan(to_sign)).value();

    shatters::Bytes buf(32 + 64 + text.size());
    std::memcpy(buf.data(), sender_pk.data(), 32);
    std::memcpy(buf.data() + 32, sig.data(), 64);
    std::memcpy(buf.data() + 96, text.data(), text.size());
    return buf;
}

struct IncomingMessage
{
    shatters::crypto::PublicKey sender_pk;
    std::string text;
};

static std::optional<IncomingMessage> parse_payload(shatters::ByteSpan data)
{
    if (data.size() < 96) // 32 pk + 64 sig
        return std::nullopt;

    shatters::crypto::PublicKey sender_pk;
    std::memcpy(sender_pk.data(), data.data(), 32);

    shatters::crypto::Signature sig;
    std::memcpy(sig.data(), data.data() + 32, 64);

    // reconstruct signed data: [pk:32 | text]
    shatters::Bytes signed_data(32 + (data.size() - 96));
    std::memcpy(signed_data.data(),      data.data(),      32);
    std::memcpy(signed_data.data() + 32, data.data() + 96, data.size() - 96);

    if (shatters::crypto::verify_signature(
            shatters::ByteSpan(signed_data), sig, sender_pk).is_err())
        return std::nullopt;

    IncomingMessage m;
    m.sender_pk = sender_pk;
    m.text.assign(reinterpret_cast<const char*>(data.data() + 96), data.size() - 96);
    return m;
}

static std::pair<std::string, std::string> split_first(const std::string& s)
{
    auto pos = s.find(' ');
    if (pos == std::string::npos)
        return {s, {}};

    return {s.substr(0, pos), s.substr(pos + 1)};
}

static shatters::storage::ContactRecord const* resolve_contact(
    const std::vector<shatters::storage::ContactRecord>& contacts,
    const std::string& query)
{
    for (const auto& c : contacts)
    {
        if (c.display_name == query ||
            c.address      == query ||
            c.address.starts_with(query))
            return &c;
    }
    return nullptr;
}

static void print_help()
{
    println(R"(
commands:
  /address            - show your address
  /add <addr> <name>  - add a contact
  /contacts           - list contacts
  /msg <name> <text>  - send an encrypted message
  /remove <name>      - remove a contact
  /help               - show this list
  /quit               - exit
)");
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    spdlog::set_level(spdlog::level::off);

    if (argc < 2)
    {
        std::cerr << "usage: chat <nickname> [host] [port]\n";
        return 1;
    }

    std::string nickname = argv[1];
    if (nickname.size() > 32)
        nickname.resize(32);

    std::string host = (argc > 2) ? argv[2] : "127.0.0.1";
    uint16_t    port = (argc > 3)
        ? static_cast<uint16_t>(std::stoi(argv[3]))
        : 4433;

    std::signal(SIGINT, on_signal);

    std::string db_path = nickname + ".shatters.db";

    shatters::ShattersClient::Config cfg;
    cfg.db_path        = db_path;
    cfg.db_pass        = "demo-" + nickname;
    cfg.server_host    = host;
    cfg.server_port    = port;
    cfg.auto_reconnect = true;

    println("* creating client...");

    auto result = shatters::ShattersClient::create(std::move(cfg));
    if (result.is_err())
    {
        std::cerr << "error: " << result.error().message << "\n";
        return 1;
    }
    auto& client = *result.value();

    const auto& my_kp   = client.identity().keypair();
    const auto& my_pk   = client.identity().public_key();
    const auto& my_x_pk = my_kp.x25519_public();
    const auto& my_x_sk = my_kp.x25519_secret();

    auto my_addr  = to_hex(my_pk.data(), my_pk.size());
    auto my_inbox = derive_inbox(my_pk);

    println("* address: " + my_addr);
    println("* share this address with your contacts.");

    client.on_connected([&]()
    {
        println("\n* connected to " + host + ":" + std::to_string(port));
        print("> ");
    });

    client.on_disconnected([](shatters::Error err)
    {
        println("\n* disconnected: " + err.message);
    });

    client.on_error([](shatters::Error err)
    {
        println("\n* error: " + err.message);
    });

    println("* connecting to " + host + ":" + std::to_string(port) + "...");
    auto status = client.connect();
    if (status.is_err())
    {
        std::cerr << "connect failed: " << status.error().message << "\n";
        return 1;
    }

    auto sub = client.subscribe(my_inbox,
        [&](const shatters::Channel&, shatters::ByteSpan data)
        {
            auto pt = seal_decrypt(data, my_x_pk, my_x_sk);
            if (pt.is_err()) return;

            auto msg = parse_payload(shatters::ByteSpan(pt.value()));
            if (!msg)
                return;

            auto sender_hex = to_hex(msg->sender_pk.data(), msg->sender_pk.size());
            std::string sender = sender_hex.substr(0, 8) + "...";

            auto cr = client.list_contacts();
            if (cr.is_ok())
            {
                for (const auto& c : cr.value())
                {
                    if (c.address == sender_hex && !c.display_name.empty())
                    {
                        sender = c.display_name;
                        break;
                    }
                }
            }

            std::lock_guard lk(g_io);
            std::cout << "\n  [" << sender << "] " << msg->text << "\n> " << std::flush;
        });

    if (sub.is_err())
    {
        std::cerr << "subscribe failed: " << sub.error().message << "\n";
        return 1;
    }
    auto sub_handle = std::move(sub).take_value();

    println("* type /help for commands.");
    print("> ");

    std::string line;
    while (g_running.load() && std::getline(std::cin, line))
    {
        if (line.empty()) { print("> "); continue; }

        if (line == "/quit" || line == "/exit")
            break;

        if (line == "/help")
        {
            print_help();
            print("> ");
            continue;
        }

        if (line == "/address")
        {
            println("  " + my_addr);
            print("> ");
            continue;
        }

        if (line.starts_with("/add "))
        {
            auto [hex_addr, name] = split_first(line.substr(5));
            if (hex_addr.size() != 64 || name.empty())
            {
                println("  usage: /add <64-char-hex-address> <name>");
                print("> ");
                continue;
            }

            shatters::crypto::PublicKey pk{};
            if (!from_hex(hex_addr, pk.data(), pk.size()))
            {
                println("  invalid hex address.");
                print("> ");
                continue;
            }

            if (hex_addr == my_addr)
            {
                println("  can't add yourself as a contact.");
                print("> ");
                continue;
            }

            auto as = client.add_contact(hex_addr, pk, name);
            if (as.is_err())
                println("  failed: " + as.error().message);
            else
                println("  contact added: " + name);
            print("> ");
            continue;
        }

        if (line == "/contacts")
        {
            auto cr = client.list_contacts();
            if (cr.is_err())
            {
                println("  error: " + cr.error().message);
                print("> ");
                continue;
            }
            auto& contacts = cr.value();
            if (contacts.empty())
            {
                println("  no contacts.");
            }
            else
            {
                println("  contacts (" + std::to_string(contacts.size()) + "):");
                for (const auto& c : contacts)
                    println("    " + c.display_name + " - " + c.address.substr(0, 16) + "...");
            }
            print("> ");
            continue;
        }

        if (line.starts_with("/remove "))
        {
            auto name = line.substr(8);
            auto cr = client.list_contacts();
            if (cr.is_err()) { println("  error."); print("> "); continue; }

            auto* contact = resolve_contact(cr.value(), name);
            if (!contact)
            {
                println("  contact not found: " + name);
                print("> ");
                continue;
            }

            auto rs = client.remove_contact(contact->address);
            if (rs.is_err())
                println("  failed: " + rs.error().message);
            else
                println("  removed.");
            print("> ");
            continue;
        }

        if (line.starts_with("/msg "))
        {
            auto [name, text] = split_first(line.substr(5));
            if (name.empty() || text.empty())
            {
                println("  usage: /msg <name> <text>");
                print("> ");
                continue;
            }

            auto cr = client.list_contacts();
            if (cr.is_err())
            {
                println("  error loading contacts.");
                print("> ");
                continue;
            }

            auto* contact = resolve_contact(cr.value(), name);
            if (!contact)
            {
                println("  contact not found: " + name);
                print("> ");
                continue;
            }

            shatters::crypto::PublicKey zero_pk{};
            if (contact->public_key == zero_pk)
            {
                println("  contact has no public key. re-add with /add <hex_addr> <name>");
                print("> ");
                continue;
            }

            auto their_x25519 = shatters::crypto::ed25519_pk_to_x25519(contact->public_key);
            if (their_x25519.is_err())
            {
                println("  crypto error: " + their_x25519.error().message);
                print("> ");
                continue;
            }

            auto payload = build_payload(my_kp, text);
            auto ct = seal_encrypt(shatters::ByteSpan(payload), their_x25519.value());

            auto their_inbox = derive_inbox(contact->public_key);
            auto ps = client.publish(their_inbox, shatters::ByteSpan(ct));

            if (ps.is_err())
                println("  send failed: " + ps.error().message);
            else
                println("  sent.");
            print("> ");
            continue;
        }

        if (line[0] == '/')
            println("  unknown command. type /help.");
        else
            println("  type /help for commands.");
        print("> ");
    }

    println("\n* bye!");
    client.disconnect();
    return 0;
}
