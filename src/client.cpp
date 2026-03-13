#include <shatters/client.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

namespace shatters
{
    struct ShattersClient::Impl
    {
        Config config;
    };

    ShattersClient::ShattersClient() : impl_(std::make_unique<Impl>()) {}

    ShattersClient::~ShattersClient() 
    {
        disconnect();
    }

    Result<std::unique_ptr<ShattersClient>> ShattersClient::create(Config config)
    {
        if (sodium_init() < 0)
            return Error{ErrorCode::CryptoError, "failed to initialize libsodium"};

        auto client = std::unique_ptr<ShattersClient>(new ShattersClient());
        
        auto& impl = *client->impl_;
        impl.config = std::move(config);

        spdlog::info("hello world!");

        return std::move(client);
    }

    Result<void> ShattersClient::connect()
    {
        return std::monostate{};
    }

    void ShattersClient::disconnect()
    {
    }

    bool ShattersClient::is_connected() const
    {
        return false;
    }
}