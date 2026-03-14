#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace shatters::framing
{

constexpr uint32_t MAX_FRAME_SIZE = 1u * 1024u * 1024u;
constexpr size_t   HEADER_SIZE    = 4;

inline std::vector<uint8_t> encode(const uint8_t* data, size_t len)
{
    if (len > MAX_FRAME_SIZE)
        return {};

    std::vector<uint8_t> frame(HEADER_SIZE + len);
    
    auto n = static_cast<uint32_t>(len);
    frame[0] = static_cast<uint8_t>((n >> 24) & 0xFF);
    frame[1] = static_cast<uint8_t>((n >> 16) & 0xFF);
    frame[2] = static_cast<uint8_t>((n >> 8)  & 0xFF);
    frame[3] = static_cast<uint8_t>( n        & 0xFF);

    if (len > 0)
        std::memcpy(frame.data() + HEADER_SIZE, data, len);

    return frame;
}

inline uint32_t decode_length(const uint8_t* header)
{
    return (static_cast<uint32_t>(header[0]) << 24) |
           (static_cast<uint32_t>(header[1]) << 16) |
           (static_cast<uint32_t>(header[2]) << 8)  |
            static_cast<uint32_t>(header[3]);
}

}
