#pragma once

#include <shatters/storage/database.hpp>
#include <shatters/types.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace shatters::storage
{

struct SessionRecord
{
    std::string contact_address;
    Bytes       encrypted_state;
    int64_t     updated_at;
};

class SessionStore
{
public:
    explicit SessionStore(Database& db) : db_(db) {}

    Status store(const SessionRecord& record);
    Status update(const SessionRecord& record);
    Result<std::optional<SessionRecord>> find(const std::string& contact_address);
    Status remove(const std::string& contact_address);

    Result<std::vector<std::string>> list_active();

private:
    Database& db_;
};

}