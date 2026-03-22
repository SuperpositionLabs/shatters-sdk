#include <shatters/storage/database.hpp>
#include <shatters/crypto/keys.hpp>

#include <sqlite3.h>
#include <sodium.h>

#include <cstring>

namespace shatters::storage
{

static constexpr const char* SCHEMA_SQL = R"SQL(
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS identity (
    id              INTEGER PRIMARY KEY,
    public_key      BLOB NOT NULL,
    encrypted_seed  BLOB NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    address      TEXT PRIMARY KEY,
    public_key   BLOB NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    added_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    contact_address TEXT PRIMARY KEY,
    encrypted_state BLOB NOT NULL,
    updated_at      INTEGER NOT NULL,
    FOREIGN KEY (contact_address) REFERENCES contacts(address)
);

CREATE TABLE IF NOT EXISTS messages (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_address   TEXT NOT NULL,
    direction         INTEGER NOT NULL,
    encrypted_content BLOB NOT NULL,
    timestamp_ms      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_contact
    ON messages(contact_address, timestamp_ms DESC);

CREATE TABLE IF NOT EXISTS prekeys (
    id                 INTEGER PRIMARY KEY,
    encrypted_secret   BLOB NOT NULL,
    public_key         BLOB NOT NULL,
    used               INTEGER NOT NULL DEFAULT 0
);
)SQL";

struct Database::Impl
{
    sqlite3*                          db = nullptr;
    crypto::SecureBuffer<crypto::AEAD_KEY_SIZE> master_key;
};

Database::~Database()
{
    if (impl_)
    {
        if (impl_->db)
            sqlite3_close(impl_->db);
    }
}

Database::Database(Database&& other) noexcept = default;
Database& Database::operator=(Database&& other) noexcept = default;

Result<Database> Database::open(const std::string& path, const std::string& password)
{
    Database database;
    database.impl_ = std::make_unique<Impl>();

    int rc = sqlite3_open(path.c_str(), &database.impl_->db);
    if (rc != SQLITE_OK)
    {
        std::string msg = sqlite3_errmsg(database.impl_->db);
        sqlite3_close(database.impl_->db);
        database.impl_->db = nullptr;
        return Error{ErrorCode::InternalError, "sqlite open failed: " + msg};
    }

    sqlite3_exec(database.impl_->db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(database.impl_->db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);

    SHATTERS_TRY(database.create_schema());

    std::array<uint8_t, crypto::ARGON2_SALT_SIZE> salt{};

    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(
        database.impl_->db,
        "SELECT value FROM metadata WHERE key = 'argon2_salt'",
        -1, &stmt, nullptr
    );
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW)
    {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int blob_len = sqlite3_column_bytes(stmt, 0);
        if (blob_len == static_cast<int>(salt.size()))
            std::memcpy(salt.data(), blob, salt.size());
    }
    sqlite3_finalize(stmt);

    bool salt_is_zero = true;
    for (auto b : salt)
    { 
        if (b != 0)
        {
            salt_is_zero = false;
            break;
        }
    }

    if (salt_is_zero)
    {
        salt = crypto::generate_salt();

        sqlite3_stmt* insert = nullptr;
        rc = sqlite3_prepare_v2(
            database.impl_->db,
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('argon2_salt', ?)",
            -1, &insert, nullptr
        );
        if (rc == SQLITE_OK)
        {
            sqlite3_bind_blob(insert, 1, salt.data(),
                              static_cast<int>(salt.size()), SQLITE_STATIC);
            sqlite3_step(insert);
        }
        sqlite3_finalize(insert);
    }

    auto key_result = crypto::derive_key_from_password(password, salt);
    SHATTERS_TRY(key_result);

    std::memcpy(database.impl_->master_key.data(), key_result.value().data(), crypto::KDF_KEY_SIZE);

    return std::move(database);
}

Result<Bytes> Database::encrypt_blob(ByteSpan plaintext) const
{
    return crypto::aead_seal(plaintext, {}, impl_->master_key.array());
}

Result<Bytes> Database::decrypt_blob(ByteSpan sealed) const
{
    return crypto::aead_open(sealed, {}, impl_->master_key.array());
}

Status Database::execute(const std::string& sql)
{
    char* err_msg = nullptr;
    int rc = sqlite3_exec(impl_->db, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK)
    {
        std::string msg = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        return Error{ErrorCode::InternalError, "sql exec failed: " + msg};
    }
    return {};
}

void* Database::raw_handle() noexcept
{
    return impl_ ? impl_->db : nullptr;
}

Status Database::create_schema()
{
    return execute(SCHEMA_SQL);
}

}