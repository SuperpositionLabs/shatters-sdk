#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/storage/database.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <vector>

namespace shatters::storage
{

    struct PreKeyRecord
    {
        uint32_t             id;
        Bytes                encrypted_secret;
        crypto::X25519Public public_key;
        bool                 used;
    };

    class PreKeyStore
    {
    public:
        explicit PreKeyStore(Database& db) : db_(db) {}

        Status store(uint32_t id, const crypto::X25519KeyPair& keypair);
        Result<std::optional<PreKeyRecord>> find(uint32_t id);
        Result<crypto::X25519KeyPair> decrypt(const PreKeyRecord& record);
        Status mark_used(uint32_t id);

        Result<std::vector<PreKeyRecord>> list_unused();

        Result<uint32_t> next_id();

        Status cleanup_used();

    private:
        Database& db_;
    };

}