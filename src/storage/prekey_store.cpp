#include <shatters/storage/prekey_store.hpp>

#include <sqlite3.h>

#include <cstring>

namespace shatters::storage
{

Status PreKeyStore::store(uint32_t id, const crypto::X25519KeyPair& keypair)
{
    auto sealed = db_.encrypt_blob(keypair.secret_key().span());
    SHATTERS_TRY(sealed);

    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO prekeys (id, encrypted_secret, public_key, used) "
        "VALUES (?, ?, ?, 0)",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    sqlite3_bind_blob(stmt, 2, sealed.value().data(), static_cast<int>(sealed.value().size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, keypair.public_key().data(), static_cast<int>(keypair.public_key().size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to store prekey"};

    return {};
}

Result<std::optional<PreKeyRecord>> PreKeyStore::find(uint32_t id)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT id, encrypted_secret, public_key, used FROM prekeys WHERE id = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_int(stmt, 1, static_cast<int>(id));

    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return std::optional<PreKeyRecord>{std::nullopt};
    }

    PreKeyRecord record{};
    record.id = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));

    const void* sec_blob = sqlite3_column_blob(stmt, 1);
    int sec_len = sqlite3_column_bytes(stmt, 1);
    record.encrypted_secret.assign(
        static_cast<const uint8_t*>(sec_blob),
        static_cast<const uint8_t*>(sec_blob) + sec_len);

    const void* pk_blob = sqlite3_column_blob(stmt, 2);
    int pk_len = sqlite3_column_bytes(stmt, 2);
    if (pk_len == static_cast<int>(record.public_key.size()))
        std::memcpy(record.public_key.data(), pk_blob, record.public_key.size());

    record.used = sqlite3_column_int(stmt, 3) != 0;

    sqlite3_finalize(stmt);
    return std::optional<PreKeyRecord>{std::move(record)};
}

Result<crypto::X25519KeyPair> PreKeyStore::decrypt(const PreKeyRecord& record)
{
    auto secret = db_.decrypt_blob(record.encrypted_secret);
    SHATTERS_TRY(secret);
    return crypto::X25519KeyPair::from_secret(secret.value());
}

Status PreKeyStore::mark_used(uint32_t id)
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "UPDATE prekeys SET used = 1 WHERE id = ?",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_int(stmt, 1, static_cast<int>(id));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to mark prekey used"};

    return {};
}

Result<std::vector<PreKeyRecord>> PreKeyStore::list_unused()
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT id, encrypted_secret, public_key, used FROM prekeys "
        "WHERE used = 0 ORDER BY id",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    std::vector<PreKeyRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        PreKeyRecord record{};
        record.id = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));

        const void* sec_blob = sqlite3_column_blob(stmt, 1);
        int sec_len = sqlite3_column_bytes(stmt, 1);
        record.encrypted_secret.assign(
            static_cast<const uint8_t*>(sec_blob),
            static_cast<const uint8_t*>(sec_blob) + sec_len
        );

        const void* pk_blob = sqlite3_column_blob(stmt, 2);
        int pk_len = sqlite3_column_bytes(stmt, 2);
        if (pk_len == static_cast<int>(record.public_key.size()))
            std::memcpy(record.public_key.data(), pk_blob, record.public_key.size());

        record.used = false;
        records.push_back(std::move(record));
    }
    sqlite3_finalize(stmt);
    return records;
}

Result<uint32_t> PreKeyStore::next_id()
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT COALESCE(MAX(id), 0) + 1 FROM prekeys",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_step(stmt);
    uint32_t next = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));
    sqlite3_finalize(stmt);
    return next;
}

Status PreKeyStore::cleanup_used()
{
    return db_.execute("DELETE FROM prekeys WHERE used = 1");
}

}