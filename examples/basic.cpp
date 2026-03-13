#include <shatters/shatters.hpp>
#include <cstdio>

int main()
{
    auto client = shatters::ShattersClient::create({
        .db_path = "shatters.db",
        .db_pass = "ALL_DOGS_GO_TO_HEAVEN",
        .server_host = "127.0.0.1",
        .server_port = 4433,
    });

    if (client.is_err()) {
        std::fprintf(stderr, "error: %s\n", client.error().message.c_str());
        return EXIT_FAILURE;
    }

    auto conn = client.value()->connect();
    if (conn.is_err()) {
        std::fprintf(stderr, "error: %s\n", conn.error().message.c_str());
        return EXIT_FAILURE;
    }
}