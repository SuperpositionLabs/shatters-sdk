#pragma once

#include <shatters/types.hpp>

#include <cstdint>

namespace shatters
{

enum class MessageType : uint8_t
{
    Publish     = 0x01,
    Subscribe   = 0x02,
    Unsubscribe = 0x03,
    Retrieve    = 0x04,

    Ack         = 0x10,
    Nack        = 0x11,

    Data        = 0x20,
};

struct Message
{
    MessageType type{};
    uint32_t    id{};
    Channel     channel{};
    Bytes       payload;
};

[[nodiscard]] Bytes           serialize(const Message& msg);
[[nodiscard]] Result<Message> deserialize(ByteSpan data);

}
