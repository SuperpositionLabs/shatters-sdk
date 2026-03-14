#include <shatters/deaddrop/deaddrop.hpp>
#include <shatters/protocol/message.hpp>
#include <shatters/messaging/session.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>

namespace shatters
{

namespace
{
    constexpr char HEX_CHARS[] = "0123456789abcdef";

    std::string bytes_to_hex(const uint8_t* data, size_t len)
    {
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i)
        {
            out.push_back(HEX_CHARS[(data[i] >> 4) & 0x0F]);
            out.push_back(HEX_CHARS[ data[i]       & 0x0F]);
        }
        return out;
    }

    Result<uint8_t> hex_nibble(char c)
    {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
        return Error{ErrorCode::InvalidArgument, "invalid hex character"};
    }

    void write_u64(uint8_t* dst, uint64_t val)
    {
        for (int i = 7; i >= 0; --i)
        {
            dst[i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
    }

    uint64_t read_u64(const uint8_t* src)
    {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i)
            val = (val << 8) | static_cast<uint64_t>(src[i]);
        return val;
    }
}

Result<DeadDropId> DeadDropId::from_bytes(ByteSpan raw)
{
    if (raw.size() != SIZE)
        return Error{ErrorCode::InvalidArgument, "deaddrop id must be exactly 32 bytes"};

    DeadDropId id;
    std::memcpy(id.bytes.data(), raw.data(), SIZE);
    
    return id;
}

Result<DeadDropId> DeadDropId::from_hex(std::string_view hex)
{
    if (hex.size() != SIZE * 2)
        return Error{ErrorCode::InvalidArgument, "deaddrop hex id must be exactly 64 characters"};

    DeadDropId id;
    for (size_t i = 0; i < SIZE; ++i)
    {
        auto hi = hex_nibble(hex[i * 2]);
        if (hi.is_err())
            return hi.error();

        auto lo = hex_nibble(hex[i * 2 + 1]);
        if (lo.is_err())
            return lo.error();

        id.bytes[i] = static_cast<uint8_t>((hi.value() << 4) | lo.value());
    }
    return id;
}

std::string DeadDropId::to_hex() const
{
    return bytes_to_hex(bytes.data(), bytes.size());
}

Bytes serialize_envelope(const Envelope& env)
{
    size_t total = DeadDropId::SIZE + 8 + env.ciphertext.size();
    Bytes out(total);
    size_t pos = 0;

    std::memcpy(out.data() + pos, env.id.bytes.data(), DeadDropId::SIZE);
    pos += DeadDropId::SIZE;

    write_u64(out.data() + pos, env.timestamp_ms);
    pos += 8;

    if (!env.ciphertext.empty())
        std::memcpy(out.data() + pos, env.ciphertext.data(), env.ciphertext.size());

    return out;
}

Result<Envelope> deserialize_envelope(ByteSpan data)
{
    constexpr size_t MIN_SIZE = DeadDropId::SIZE + 8;

    if (data.size() < MIN_SIZE)
        return Error{ErrorCode::ProtocolError, "envelope too short"};

    Envelope env;
    size_t pos = 0;

    std::memcpy(env.id.bytes.data(), data.data() + pos, DeadDropId::SIZE);
    pos += DeadDropId::SIZE;

    env.timestamp_ms = read_u64(data.data() + pos);
    pos += 8;

    if (pos < data.size())
        env.ciphertext.assign(data.data() + pos, data.data() + data.size());

    return env;
}

DeadDropHandle::DeadDropHandle(DeadDropId id, SubscriptionHandle sub)
    : id_(id)
    , sub_(std::move(sub))
{
}

struct DeadDropService::Impl
{
    Session& session;

    explicit Impl(Session& s) : session(s) {}
};

DeadDropService::DeadDropService(Session& session)
    : impl_(std::make_unique<Impl>(session))
{
}

DeadDropService::~DeadDropService() = default;

Status DeadDropService::drop(const DeadDropId& id, ByteSpan ciphertext)
{
    Envelope env;
    env.id         = id;
    env.ciphertext = Bytes(ciphertext.begin(), ciphertext.end());

    auto payload = serialize_envelope(env);
    return impl_->session.publish(id.channel(), ByteSpan(payload));
}

Result<DeadDropHandle> DeadDropService::watch(const DeadDropId& id, DeadDropCallback cb)
{
    auto sub = impl_->session.subscribe(id.channel(),
        [cb = std::move(cb)](const Channel& /*channel*/, ByteSpan payload)
        {
            auto result = deserialize_envelope(payload);
            if (result.is_err())
            {
                spdlog::warn("deaddrop: bad envelope: {}", result.error().message);
                return;
            }
            cb(result.value());
        });

    if (sub.is_err())
        return sub.error();

    return DeadDropHandle(id, std::move(sub).take_value());
}

Status DeadDropService::unwatch(DeadDropHandle&& handle)
{
    if (!handle.valid())
        return Status{};

    handle.release();
    return Status{};
}

Status DeadDropService::retrieve(const DeadDropId& id, std::chrono::seconds ttl_hint, DeadDropCallback cb)
{
    auto sub = impl_->session.subscribe(id.channel(),
        [cb = std::move(cb)](const Channel& /*channel*/, ByteSpan payload)
        {
            auto result = deserialize_envelope(payload);
            if (result.is_err())
            {
                spdlog::warn("deaddrop retrieve: bad envelope: {}", result.error().message);
                return;
            }
            cb(result.value());
        });

    if (sub.is_err())
        return sub.error();

    auto ttl_sec = static_cast<uint32_t>(ttl_hint.count());
    Bytes ttl_payload(4);
    ttl_payload[0] = static_cast<uint8_t>((ttl_sec >> 24) & 0xFF);
    ttl_payload[1] = static_cast<uint8_t>((ttl_sec >> 16) & 0xFF);
    ttl_payload[2] = static_cast<uint8_t>((ttl_sec >> 8)  & 0xFF);
    ttl_payload[3] = static_cast<uint8_t>( ttl_sec        & 0xFF);

    return impl_->session.retrieve(id.channel(), ByteSpan(ttl_payload));
}

}
