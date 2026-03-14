#pragma once

#include <shatters/crypto/aead.hpp>
#include <shatters/crypto/kdf.hpp>
#include <shatters/types.hpp>

#include <memory>
#include <string>

namespace shatters::storage
{

    class Database
    {
        public:
            ~Database();

            Database(const Database&) = delete;
            Database& operator=(const Database&) = delete;
            Database(Database&&) noexcept;
            Database& operator=(Database&&) noexcept;

            static Result<Database> open(const std::string& path, const std::string& password);

            Result<Bytes> encrypt_blob(ByteSpan plaintext) const;
            Result<Bytes> decrypt_blob(ByteSpan sealed) const;

            Status execute(const std::string& sql);

            void* raw_handle() noexcept;

        private:
            Database() = default;
            Status create_schema();

            struct Impl;
            std::unique_ptr<Impl> impl_;
    };

}