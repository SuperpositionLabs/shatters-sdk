#pragma once

#include <shatters/crypto/keys.hpp>
#include <shatters/types.hpp>

#include <array>
#include <string>

namespace shatters::identity
{

class ContactAddress
{
public:
    static constexpr size_t HASH_TRUNCATED_SIZE = 20;
    static constexpr size_t RAW_SIZE = 1 + HASH_TRUNCATED_SIZE + 2;

    static ContactAddress from_public_key(const crypto::PublicKey& public_key);

    static Result<ContactAddress> from_string(const std::string& address_str);

    [[nodiscard]] const std::string& to_string() const noexcept { return address_str_; }

    [[nodiscard]] const std::array<uint8_t, RAW_SIZE>& raw() const noexcept { return raw_; }

    [[nodiscard]] uint8_t version() const noexcept { return raw_[0]; }

    [[nodiscard]] Channel intro_channel() const;

    bool operator==(const ContactAddress& other) const noexcept
    {
        return raw_ == other.raw_;
    }

    bool operator!=(const ContactAddress& other) const noexcept
    {
        return !(*this == other);
    }

private:
    std::array<uint8_t, RAW_SIZE> raw_{};
    std::string address_str_;
};

}