#include <shatters/storage/contact_store.hpp>

#include <sqlite3.h>

#include <chrono>
#include <cstring>

namespace shatters::storage
{

Status ContactStore::store(const ContactRecord& contact)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO contacts (address, public_key, display_name, added_at) "
        "VALUES (?, ?, ?, ?)",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, contact.address.c_str(),      static_cast<int>(contact.address.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, contact.public_key.data(),    static_cast<int>(contact.public_key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, contact.display_name.c_str(), static_cast<int>(contact.display_name.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, contact.added_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to store contact"};

    return {};
}

Status ContactStore::remove(const std::string& address)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    sqlite3_stmt* del_sessions = nullptr;
    sqlite3_prepare_v2(db,
        "DELETE FROM sessions WHERE contact_address = ?",
        -1, &del_sessions, nullptr);
    if (del_sessions)
    {
        sqlite3_bind_text(del_sessions, 1, address.c_str(), static_cast<int>(address.size()), SQLITE_STATIC);
        sqlite3_step(del_sessions);
        sqlite3_finalize(del_sessions);
    }

    sqlite3_stmt* del_messages = nullptr;
    sqlite3_prepare_v2(db,
        "DELETE FROM messages WHERE contact_address = ?",
        -1, &del_messages, nullptr);
    if (del_messages)
    {
        sqlite3_bind_text(del_messages, 1, address.c_str(), static_cast<int>(address.size()), SQLITE_STATIC);
        sqlite3_step(del_messages);
        sqlite3_finalize(del_messages);
    }

    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM contacts WHERE address = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, address.c_str(), static_cast<int>(address.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to remove contact"};

    return {};
}

Result<std::optional<ContactRecord>> ContactStore::find(const std::string& address)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT address, public_key, display_name, added_at FROM contacts WHERE address = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, address.c_str(),
                      static_cast<int>(address.size()), SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return std::optional<ContactRecord>{std::nullopt};
    }

    ContactRecord record{};
    record.address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

    const void* pk_blob = sqlite3_column_blob(stmt, 1);
    int pk_len = sqlite3_column_bytes(stmt, 1);
    if (pk_len == static_cast<int>(record.public_key.size()))
        std::memcpy(record.public_key.data(), pk_blob, record.public_key.size());

    const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    if (name)
        record.display_name = name;

    record.added_at = sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return std::optional<ContactRecord>{std::move(record)};
}

Result<std::vector<ContactRecord>> ContactStore::list_all()
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT address, public_key, display_name, added_at FROM contacts ORDER BY added_at",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    std::vector<ContactRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        ContactRecord record{};
        record.address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        const void* pk_blob = sqlite3_column_blob(stmt, 1);
        int pk_len = sqlite3_column_bytes(stmt, 1);
        if (pk_len == static_cast<int>(record.public_key.size()))
            std::memcpy(record.public_key.data(), pk_blob, record.public_key.size());

        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (name) record.display_name = name;

        record.added_at = sqlite3_column_int64(stmt, 3);
        records.push_back(std::move(record));
    }
    sqlite3_finalize(stmt);
    return records;
}

}