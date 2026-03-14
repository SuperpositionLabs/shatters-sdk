#pragma once

#include <shatters/messaging/subscription.hpp>
#include <shatters/types.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace shatters
{

class Session;

struct DeadDropId
{
    static constexpr size_t SIZE = CHANNEL_SIZE;

    Channel bytes{};

    static Result<DeadDropId> from_bytes(ByteSpan raw);
    static Result<DeadDropId> from_hex(std::string_view hex);

    [[nodiscard]] std::string to_hex() const;

    [[nodiscard]] ByteSpan        span()    const { return {bytes.data(), bytes.size()}; }
    [[nodiscard]] const Channel&  channel() const { return bytes; }

    bool operator==(const DeadDropId& o) const = default;
    bool operator!=(const DeadDropId& o) const = default;
};

struct Envelope
{
    DeadDropId id;
    Bytes      ciphertext;
    uint64_t   timestamp_ms{0};
};

[[nodiscard]] Bytes            serialize_envelope(const Envelope& env);
[[nodiscard]] Result<Envelope> deserialize_envelope(ByteSpan data);

using DeadDropCallback = std::function<void(const Envelope& env)>;

class DeadDropHandle
{
public:
    DeadDropHandle() = default;
    ~DeadDropHandle() = default;

    DeadDropHandle(DeadDropHandle&&) noexcept = default;
    DeadDropHandle& operator=(DeadDropHandle&&) noexcept = default;

    DeadDropHandle(const DeadDropHandle&) = delete;
    DeadDropHandle& operator=(const DeadDropHandle&) = delete;

    [[nodiscard]] const DeadDropId& id()    const noexcept { return id_; }
    [[nodiscard]] bool              valid() const noexcept { return sub_.valid(); }
    explicit operator bool()                const noexcept { return valid(); }

    void release() noexcept { sub_.release(); }

private:
    friend class DeadDropService;
    DeadDropHandle(DeadDropId id, SubscriptionHandle sub);

    DeadDropId         id_{};
    SubscriptionHandle sub_;
};

class DeadDropService
{
public:
    explicit DeadDropService(Session& session);
    ~DeadDropService();

    DeadDropService(const DeadDropService&) = delete;
    DeadDropService& operator=(const DeadDropService&) = delete;

    Status drop(const DeadDropId& id, ByteSpan ciphertext);

    Result<DeadDropHandle> watch(const DeadDropId& id, DeadDropCallback cb);
    Status unwatch(DeadDropHandle&& handle);

    Status retrieve(const DeadDropId& id, std::chrono::seconds ttl_hint, DeadDropCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
