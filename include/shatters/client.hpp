#pragma once

#include <shatters/types.hpp>

#include <memory>
#include <string>

namespace shatters
{
    class ShattersClient
    {
        public:
            struct Config
            {
                std::string db_path;
                std::string db_pass;

                std::string server_host;
                uint16_t    server_port = 443;

                std::vector<uint8_t> server_pubkey;
                std::vector<uint8_t> tls_pin_sha256;

                bool auto_reconnect = true;
            };

            ~ShattersClient();

            /// Creates a new client instance.
            /// If no identity exists in database, generates a new one.
            static Result<std::unique_ptr<ShattersClient>> create(Config config);

            Result<void> connect();
            void disconnect();
            
            bool is_connected() const;
        private:
            ShattersClient();

            struct Impl;
            std::unique_ptr<Impl> impl_;
    };
}