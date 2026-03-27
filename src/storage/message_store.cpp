#include <shatters/storage/message_store.hpp>

#include <sqlite3.h>

#include <cstring>

namespace shatters::storage
{

Status MessageStore::store(
    const std::string& contact_address,
    uint8_t direction,
    ByteSpan plaintext,
    int64_t timestamp_ms)
{
    auto sealed = db_.encrypt_blob(plaintext);
    SHATTERS_TRY(sealed);

    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO messages (contact_address, direction, encrypted_content, timestamp_ms) "
        "VALUES (?, ?, ?, ?)",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, contact_address.c_str(), static_cast<int>(contact_address.size()), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, direction);
    sqlite3_bind_blob(stmt, 3, sealed.value().data(), static_cast<int>(sealed.value().size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, timestamp_ms);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to store message"};

    return {};
}

Result<std::vector<MessageRecord>> MessageStore::list(
    const std::string& contact_address,
    size_t limit,
    size_t offset)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT id, contact_address, direction, encrypted_content, timestamp_ms "
        "FROM messages WHERE contact_address = ? "
        "ORDER BY timestamp_ms ASC LIMIT ? OFFSET ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, contact_address.c_str(), static_cast<int>(contact_address.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, static_cast<int64_t>(limit));
    sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(offset));

    std::vector<MessageRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        MessageRecord record{};
        record.id = sqlite3_column_int64(stmt, 0);
        record.contact_address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        record.direction = static_cast<uint8_t>(sqlite3_column_int(stmt, 2));

        const void* ct_blob = sqlite3_column_blob(stmt, 3);
        int ct_len = sqlite3_column_bytes(stmt, 3);
        record.encrypted_content.assign(
            static_cast<const uint8_t*>(ct_blob),
            static_cast<const uint8_t*>(ct_blob) + ct_len
        );

        record.timestamp_ms = sqlite3_column_int64(stmt, 4);
        records.push_back(std::move(record));
    }
    sqlite3_finalize(stmt);
    return records;
}

Status MessageStore::remove_all(const std::string& contact_address)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "DELETE FROM messages WHERE contact_address = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_text(stmt, 1, contact_address.c_str(), static_cast<int>(contact_address.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to remove messages"};

    return {};
}

}