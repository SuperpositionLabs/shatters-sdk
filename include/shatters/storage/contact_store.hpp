#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/storage/database.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace shatters::storage
{
    struct ContactRecord
    {
        std::string          address;
        crypto::PublicKey     public_key;
        std::string          display_name;
        int64_t              added_at;
    };

    class ContactStore
    {
        public:
            explicit ContactStore(Database& db) : db_(db) {}

            Status store(const ContactRecord& contact);
            Status remove(const std::string& address);
            
            Result<std::optional<ContactRecord>> find(const std::string& address);
            Result<std::vector<ContactRecord>> list_all();

    private:
        Database& db_;
    };
}