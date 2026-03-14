#pragma once

#include <shatters/storage/database.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace shatters::storage
{
    struct MessageRecord
    {
        int64_t     id;
        std::string contact_address;
        uint8_t     direction;
        Bytes       encrypted_content;
        int64_t     timestamp_ms;
    };

    class MessageStore
    {
        public:
            explicit MessageStore(Database& db) : db_(db) {}

            Status store(const std::string& contact_address,
                        uint8_t direction,
                        ByteSpan plaintext,
                        int64_t timestamp_ms);

            Result<std::vector<MessageRecord>> list(
                const std::string& contact_address,
                size_t limit,
                size_t offset = 0);

            Status remove_all(const std::string& contact_address);

        private:
            Database& db_;
    };
}