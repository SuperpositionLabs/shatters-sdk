#include <shatters/storage/session_store.hpp>

#include <sqlite3.h>

#include <chrono>
#include <cstring>

namespace shatters::storage
{

Status SessionStore::store(const SessionRecord& record)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO sessions (contact_address, encrypted_state, updated_at) "
        "VALUES (?, ?, ?)",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, record.contact_address.c_str(), static_cast<int>(record.contact_address.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, record.encrypted_state.data(), static_cast<int>(record.encrypted_state.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, record.updated_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to store session"};

    return {};
}

Status SessionStore::update(const SessionRecord& record)
{
    return store(record);
}

Result<std::optional<SessionRecord>> SessionStore::find(const std::string& contact_address)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT contact_address, encrypted_state, updated_at FROM sessions "
        "WHERE contact_address = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, contact_address.c_str(), static_cast<int>(contact_address.size()), SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return std::optional<SessionRecord>{std::nullopt};
    }

    SessionRecord record{};
    record.contact_address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

    const void* state_blob = sqlite3_column_blob(stmt, 1);
    int state_len = sqlite3_column_bytes(stmt, 1);
    record.encrypted_state.assign(
        static_cast<const uint8_t*>(state_blob),
        static_cast<const uint8_t*>(state_blob) + state_len
    );

    record.updated_at = sqlite3_column_int64(stmt, 2);

    sqlite3_finalize(stmt);
    return std::optional<SessionRecord>{std::move(record)};
}

Status SessionStore::remove(const std::string& contact_address)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM sessions WHERE contact_address = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, contact_address.c_str(), static_cast<int>(contact_address.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to remove session"};

    return {};
}

Result<std::vector<std::string>> SessionStore::list_active()
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT contact_address FROM sessions ORDER BY updated_at DESC",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    std::vector<std::string> addresses;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        auto* addr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (addr) addresses.emplace_back(addr);
    }
    sqlite3_finalize(stmt);
    return addresses;
}

}