#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/identity/address.hpp>
#include <shatters/storage/database.hpp>
#include <shatters/storage/identity_store.hpp>
#include <shatters/types.hpp>

#include <memory>

namespace shatters::identity
{

class Identity
{
public:
    static Result<Identity> load_or_create(storage::Database& db);

    [[nodiscard]] const crypto::IdentityKeyPair& keypair() const noexcept
    {
        return keypair_;
    }

    [[nodiscard]] const ContactAddress& address() const noexcept
    {
        return address_;
    }

    [[nodiscard]] const crypto::PublicKey& public_key() const noexcept
    {
        return keypair_.ed25519_public();
    }

    [[nodiscard]] const crypto::X25519Public& dh_public_key() const noexcept
    {
        return keypair_.x25519_public();
    }

private:
    Identity(crypto::IdentityKeyPair keypair, ContactAddress address)
        : keypair_(std::move(keypair)), address_(std::move(address)) {}

    crypto::IdentityKeyPair keypair_;
    ContactAddress          address_;
};

}