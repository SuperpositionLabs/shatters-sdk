#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/storage/database.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <optional>

namespace shatters::storage
{

    struct IdentityRecord
    {
        int64_t                 id;
        crypto::PublicKey        public_key;
        Bytes                   encrypted_seed;
        int64_t                 created_at;
    };

    class IdentityStore
    {
        public:
            explicit IdentityStore(Database& db) : db_(db) {}

            Status store(const crypto::IdentityKeyPair& keypair);

            Result<std::optional<IdentityRecord>> load();

            Result<crypto::IdentityKeyPair> decrypt(const IdentityRecord& record);

            Result<bool> exists();

        private:
            Database& db_;
    };

}