#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

namespace shatters
{
    enum class ErrorCode
    {
        Ok = 0,
        CryptoError,
    };

    struct Error
    {
        ErrorCode code;
        std::string message;

        explicit operator bool() const { return code != ErrorCode::Ok; }
    };

    template <typename T>
    class Result
    {
        using Storage = std::conditional_t<std::is_void_v<T>, std::monostate, T>;

    public:
        Result(Storage value) : data_(std::move(value)) {}
        Result(Error error)   : data_(std::move(error)) {}

        bool is_ok()  const { return std::holds_alternative<Storage>(data_); }
        bool is_err() const { return std::holds_alternative<Error>(data_); }

        const Storage& value() const & requires (!std::is_void_v<T>) { return std::get<Storage>(data_); }
        Storage&       value()       & requires (!std::is_void_v<T>) { return std::get<Storage>(data_); }
        Storage    take_value()     && requires (!std::is_void_v<T>) { return std::move(std::get<Storage>(data_)); }

        const Error& error() const { return std::get<Error>(data_); }

    private:
        std::variant<Storage, Error> data_;
    };

}

/// Propagate errors, rust like `?` op.
#define SHATTERS_TRY(expr)                            \
    do {                                              \
        auto&& _res = (expr);                         \
        if (_res.is_err()) return _res.error();       \
    } while (0)