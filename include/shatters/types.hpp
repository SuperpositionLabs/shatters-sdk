#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace shatters
{

constexpr size_t CHANNEL_SIZE = 32;
using Channel = std::array<uint8_t, CHANNEL_SIZE>;

struct ChannelHash
{
    size_t operator()(const Channel& c) const noexcept
    {
        size_t h{};
        std::memcpy(&h, c.data(), sizeof(h));
        return h;
    }
};

enum class ErrorCode : uint8_t
{
    Ok = 0,
    CryptoError,
    NetworkError,
    InvalidArgument,
    Timeout,
    ConnectionClosed,
    AlreadyConnected,
    NotConnected,
    ChannelError,
    ProtocolError,
    InternalError,
    BufferOverflow,
};

struct Error
{
    ErrorCode   code;
    std::string message;

    explicit operator bool() const noexcept { return code != ErrorCode::Ok; }
};

template <typename T>
class Result
{
public:
    Result(T value)   : inner_(std::move(value)) {}
    Result(Error err) : inner_(std::unexpected(std::move(err))) {}
    Result(std::unexpected<Error> u) : inner_(std::move(u)) {}

    [[nodiscard]] bool is_ok()  const noexcept { return  inner_.has_value(); }
    [[nodiscard]] bool is_err() const noexcept { return !inner_.has_value(); }

    const T& value() const &  { return inner_.value(); }
    T&       value()       &  { return inner_.value(); }
    T&&      value()       && { return std::move(inner_).value(); }

    const Error& error() const { return inner_.error(); }

    T take_value() && { return std::move(inner_).value(); }

    explicit operator bool() const noexcept { return is_ok(); }

private:
    std::expected<T, Error> inner_;
};

template <>
class Result<void>
{
public:
    Result() = default;
    Result(Error err) : inner_(std::unexpected(std::move(err))) {}
    Result(std::unexpected<Error> u) : inner_(std::move(u)) {}

    [[nodiscard]] bool is_ok()  const noexcept { return  inner_.has_value(); }
    [[nodiscard]] bool is_err() const noexcept { return !inner_.has_value(); }

    const Error& error() const { return inner_.error(); }

    explicit operator bool() const noexcept { return is_ok(); }

private:
    std::expected<void, Error> inner_;
};

using Status = Result<void>;

using Bytes    = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;

}

#define SHATTERS_TRY(expr)                       \
    do {                                         \
        auto&& _shatters_try_r_ = (expr);        \
        if (_shatters_try_r_.is_err())           \
            return _shatters_try_r_.error();     \
    } while (0)