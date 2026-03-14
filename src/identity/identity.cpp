#include <shatters/identity/identity.hpp>

#include <spdlog/spdlog.h>

namespace shatters::identity
{

Result<Identity> Identity::load_or_create(storage::Database& db)
{
    storage::IdentityStore store(db);

    auto exists_r = store.exists();
    SHATTERS_TRY(exists_r);

    if (exists_r.value())
    {
        auto record_r = store.load();
        SHATTERS_TRY(record_r);

        if (!record_r.value().has_value())
            return Error{ErrorCode::InternalError, "identity exists but load returned empty"};

        auto kp = store.decrypt(record_r.value().value());
        SHATTERS_TRY(kp);

        auto keypair = std::move(kp).take_value();
        auto address = ContactAddress::from_public_key(keypair.ed25519_public());

        spdlog::info("loaded identity: {}", address.to_string());
        return Identity(std::move(keypair), std::move(address));
    }
    else
    {
        auto kp = crypto::IdentityKeyPair::generate();
        SHATTERS_TRY(kp);

        auto keypair = std::move(kp).take_value();
        auto address = ContactAddress::from_public_key(keypair.ed25519_public());

        SHATTERS_TRY(store.store(keypair));

        spdlog::info("generated new identity: {}", address.to_string());
        return Identity(std::move(keypair), std::move(address));
    }
}

} 