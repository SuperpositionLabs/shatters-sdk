#include <shatters/protocol/message.hpp>

#include <cstring>

namespace shatters
{

namespace
{
    void write_u32(uint8_t* dst, uint32_t val)
    {
        dst[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
        dst[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
        dst[2] = static_cast<uint8_t>((val >> 8)  & 0xFF);
        dst[3] = static_cast<uint8_t>( val        & 0xFF);
    }

    uint32_t read_u32(const uint8_t* src)
    {
        return (static_cast<uint32_t>(src[0]) << 24) |
               (static_cast<uint32_t>(src[1]) << 16) |
               (static_cast<uint32_t>(src[2]) << 8)  |
                static_cast<uint32_t>(src[3]);
    }
}

Bytes serialize(const Message& msg)
{
    constexpr size_t HEADER = 1 + 4 + CHANNEL_SIZE;
    size_t total = HEADER + msg.payload.size();

    Bytes out(total);
    size_t pos = 0;

    out[pos++] = static_cast<uint8_t>(msg.type);

    write_u32(out.data() + pos, msg.id);
    pos += 4;

    std::memcpy(out.data() + pos, msg.channel.data(), CHANNEL_SIZE);
    pos += CHANNEL_SIZE;

    if (!msg.payload.empty())
        std::memcpy(out.data() + pos, msg.payload.data(), msg.payload.size());

    return out;
}

Result<Message> deserialize(ByteSpan data)
{
    constexpr size_t MIN_HEADER = 1 + 4 + CHANNEL_SIZE;

    if (data.size() < MIN_HEADER)
        return Error{ErrorCode::ProtocolError, "message too short"};

    Message msg;
    size_t pos = 0;

    msg.type = static_cast<MessageType>(data[pos++]);

    msg.id = read_u32(data.data() + pos);
    pos += 4;

    std::memcpy(msg.channel.data(), data.data() + pos, CHANNEL_SIZE);
    pos += CHANNEL_SIZE;

    if (pos < data.size())
        msg.payload.assign(data.data() + pos, data.data() + data.size());

    return msg;
}

}