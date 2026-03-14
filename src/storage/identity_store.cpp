#include <shatters/storage/identity_store.hpp>

#include <sqlite3.h>

#include <chrono>
#include <cstring>

namespace shatters::storage
{

Status IdentityStore::store(const crypto::IdentityKeyPair& keypair)
{
    auto seed = keypair.seed();
    auto sealed = db_.encrypt_blob(seed.span());
    SHATTERS_TRY(sealed);

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO identity (public_key, encrypted_seed, created_at) VALUES (?, ?, ?)",
        -1, &stmt, nullptr
    );
    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_bind_blob(stmt, 1, keypair.ed25519_public().data(), static_cast<int>(keypair.ed25519_public().size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, sealed.value().data(), static_cast<int>(sealed.value().size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return Error{ErrorCode::InternalError, "failed to store identity"};

    return {};
}

Result<std::optional<IdentityRecord>> IdentityStore::load()
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT id, public_key, encrypted_seed, created_at FROM identity ORDER BY id LIMIT 1",
        -1, &stmt, nullptr);

    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return std::optional<IdentityRecord>{std::nullopt};
    }

    IdentityRecord record{};
    record.id = sqlite3_column_int64(stmt, 0);

    const void* pk_blob = sqlite3_column_blob(stmt, 1);
    int pk_len = sqlite3_column_bytes(stmt, 1);
    if (pk_len == static_cast<int>(record.public_key.size()))
        std::memcpy(record.public_key.data(), pk_blob, record.public_key.size());

    const void* seed_blob = sqlite3_column_blob(stmt, 2);
    int seed_len = sqlite3_column_bytes(stmt, 2);
    record.encrypted_seed.assign(
        static_cast<const uint8_t*>(seed_blob),
        static_cast<const uint8_t*>(seed_blob) + seed_len);

    record.created_at = sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return std::optional<IdentityRecord>{std::move(record)};
}

Result<crypto::IdentityKeyPair> IdentityStore::decrypt(const IdentityRecord& record)
{
    auto seed = db_.decrypt_blob(record.encrypted_seed);
    SHATTERS_TRY(seed);
    return crypto::IdentityKeyPair::from_seed(seed.value());
}

Result<bool> IdentityStore::exists()
{
    auto* db = static_cast<sqlite3*>(db_.raw_handle());
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM identity",
        -1, &stmt, nullptr);

    if (rc != SQLITE_OK)
        return Error{ErrorCode::InternalError, sqlite3_errmsg(db)};

    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return count > 0;
}

}