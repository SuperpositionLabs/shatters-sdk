#include <shatters/client.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

static std::atomic<bool> g_running{true};
static void on_signal(int) { g_running.store(false); }

static shatters::Channel derive_channel(const std::string& room)
{
    shatters::Channel ch{};
    crypto_generichash(
        ch.data(), ch.size(),
        reinterpret_cast<const unsigned char*>(room.data()), room.size(),
        nullptr, 0
    );
    return ch;
}

static std::vector<uint8_t> encode_payload(
    const std::string& nick,
    const std::string& text)
{
    auto nick_len = static_cast<uint8_t>(nick.size());
    
    std::vector<uint8_t> buf;
    buf.reserve(1 + nick.size() + text.size());
    buf.push_back(nick_len);
    buf.insert(buf.end(), nick.begin(), nick.end());
    buf.insert(buf.end(), text.begin(), text.end());
    
    return buf;
}

struct DecodedMessage
{
    std::string nick;
    std::string text;
};

static std::optional<DecodedMessage> decode_payload(shatters::ByteSpan data)
{
    if (data.empty()) return std::nullopt;
    uint8_t nick_len = data[0];
    if (1u + nick_len > data.size()) return std::nullopt;

    DecodedMessage m;
    m.nick.assign(reinterpret_cast<const char*>(data.data() + 1), nick_len);
    
    auto text_off = static_cast<size_t>(1 + nick_len);
    if (text_off < data.size())
        m.text.assign(reinterpret_cast<const char*>(data.data() + text_off), data.size() - text_off);

    return m;
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    spdlog::set_level(spdlog::level::off);

    if (argc < 2)
    {
        std::cerr << "usage: chat <nickname> [host] [port] [room]\n";
        return 1;
    }

    std::string nickname = argv[1];
    if (nickname.size() > 255)
        nickname.resize(255);

    std::string host = (argc > 2) ? argv[2] : "127.0.0.1";
    uint16_t    port = (argc > 3)
        ? static_cast<uint16_t>(std::stoi(argv[3]))
        : 4433;
    std::string room = (argc > 4) ? argv[4] : "lobby";

    std::signal(SIGINT, on_signal);

    shatters::ShattersClient::Config cfg;
    cfg.server_host    = host;
    cfg.server_port    = port;
    cfg.auto_reconnect = true;

    auto result = shatters::ShattersClient::create(std::move(cfg));
    if (result.is_err())
    {
        std::cerr << "error: " << result.error().message << "\n";
        return 1;
    }
    auto& client = *result.value();

    shatters::Channel channel = derive_channel(room);

    std::mutex io_mu;

    client.on_connected([&]()
    {
        std::lock_guard lk(io_mu);
        std::cout << "* connected to " << host << ":" << port << "\n"
                  << "* room: " << room << "\n"
                  << "* type a message and press enter. ctrl+c to quit.\n"
                  << std::flush;
    });

    client.on_disconnected([&](shatters::Error err)
    {
        std::lock_guard lk(io_mu);
        std::cout << "* disconnected: " << err.message << "\n" << std::flush;
    });

    client.on_error([&](shatters::Error err)
    {
        std::lock_guard lk(io_mu);
        std::cerr << "* error: " << err.message << "\n" << std::flush;
    });

    auto status = client.connect();
    if (status.is_err())
    {
        std::cerr << "connect failed: " << status.error().message << "\n";
        return 1;
    }

    auto sub_result = client.subscribe(
        channel,
        [&](const shatters::Channel& /*ch*/, shatters::ByteSpan payload)
        {
            auto msg = decode_payload(payload);
            if (!msg)
                return;

            if (msg->nick == nickname)
                return;

            std::lock_guard lk(io_mu);
            std::cout << "[" << msg->nick << "] " << msg->text << "\n" << std::flush;
        });

    if (sub_result.is_err())
    {
        std::cerr << "subscribe failed: " << sub_result.error().message << "\n";
        return 1;
    }
    auto sub_handle = std::move(sub_result).take_value();

    std::string line;
    while (g_running.load() && std::getline(std::cin, line))
    {
        if (line.empty())
            continue;

        auto payload = encode_payload(nickname, line);
        auto pub_status = client.publish(
            channel,
            shatters::ByteSpan(payload.data(), payload.size())
        );

        if (pub_status.is_err())
        {
            std::lock_guard lk(io_mu);
            std::cerr << "* send failed: " << pub_status.error().message
                      << "\n";
        }
    }

    std::cout << "\n* bye!\n";
    client.disconnect();
    return 0;
}
