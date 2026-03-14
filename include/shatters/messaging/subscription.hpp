#pragma once

#include <shatters/types.hpp>

#include <cstdint>
#include <functional>
#include <memory>

namespace shatters
{

using SubscriptionId = uint64_t;

using MessageCallback = std::function<void(const Channel& channel, ByteSpan payload)>;

class Session;

class SubscriptionHandle
{
public:
    SubscriptionHandle() = default;
    ~SubscriptionHandle();

    SubscriptionHandle(SubscriptionHandle&& other) noexcept;
    SubscriptionHandle& operator=(SubscriptionHandle&& other) noexcept;

    SubscriptionHandle(const SubscriptionHandle&) = delete;
    SubscriptionHandle& operator=(const SubscriptionHandle&) = delete;

    [[nodiscard]] SubscriptionId id()    const noexcept { return id_; }
    [[nodiscard]] bool           valid() const noexcept { return id_ != 0; }
    explicit operator bool()             const noexcept { return valid(); }

    void release() noexcept;

private:
    friend class Session;
    SubscriptionHandle(SubscriptionId id, Session* session, std::weak_ptr<bool> alive);

    SubscriptionId      id_{0};
    Session*            session_{nullptr};
    std::weak_ptr<bool> alive_;
};

}
