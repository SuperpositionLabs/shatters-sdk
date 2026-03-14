#pragma once

#include <shatters/types.hpp>

#include <array>
#include <cstdint>
#include <optional>

namespace shatters::crypto
{

constexpr size_t ED25519_PUBLIC_KEY_SIZE  = 32;
constexpr size_t ED25519_SECRET_KEY_SIZE  = 64;
constexpr size_t ED25519_SIGNATURE_SIZE   = 64;
constexpr size_t ED25519_SEED_SIZE        = 32;
constexpr size_t X25519_KEY_SIZE          = 32;
constexpr size_t X25519_SHARED_SIZE       = 32;

template <size_t N>
class SecureBuffer
{
public:
    SecureBuffer()  noexcept { data_.fill(0); }
    ~SecureBuffer() noexcept;

    SecureBuffer(const SecureBuffer& other)            noexcept = default;
    SecureBuffer& operator=(const SecureBuffer& other) noexcept = default;
    SecureBuffer(SecureBuffer&& other)                 noexcept;
    SecureBuffer& operator=(SecureBuffer&& other)      noexcept;

    [[nodiscard]] uint8_t*       data()   noexcept       { return data_.data(); }
    [[nodiscard]] const uint8_t* data()   const noexcept { return data_.data(); }
    [[nodiscard]] constexpr size_t size() const noexcept { return N; }

    [[nodiscard]] ByteSpan span() const noexcept
    {
        return {data_.data(), N};
    }

    [[nodiscard]] const std::array<uint8_t, N>& array() const noexcept
    {
        return data_;
    }

private:
    std::array<uint8_t, N> data_;
};

using PublicKey  = std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>;
using SecretKey  = SecureBuffer<ED25519_SECRET_KEY_SIZE>;
using Seed       = SecureBuffer<ED25519_SEED_SIZE>;
using Signature  = std::array<uint8_t, ED25519_SIGNATURE_SIZE>;
using X25519Public  = std::array<uint8_t, X25519_KEY_SIZE>;
using X25519Secret  = SecureBuffer<X25519_KEY_SIZE>;
using SharedSecret  = SecureBuffer<X25519_SHARED_SIZE>;

class IdentityKeyPair
{
public:
    static Result<IdentityKeyPair> generate();

    static Result<IdentityKeyPair> from_seed(ByteSpan seed);

    [[nodiscard]] const PublicKey&    ed25519_public()  const noexcept { return ed_public_; }
    [[nodiscard]] const SecretKey&    ed25519_secret()  const noexcept { return ed_secret_; }
    [[nodiscard]] const X25519Public& x25519_public()   const noexcept { return x_public_; }
    [[nodiscard]] const X25519Secret& x25519_secret()   const noexcept { return x_secret_; }

    Result<Signature> sign(ByteSpan message) const;

    Seed seed() const;

private:
    IdentityKeyPair() = default;
    Status derive_x25519();

    PublicKey    ed_public_{};
    SecretKey    ed_secret_;
    X25519Public x_public_{};
    X25519Secret x_secret_;
};

class X25519KeyPair
{
public:
    static Result<X25519KeyPair> generate();

    [[nodiscard]] const X25519Public& public_key()  const noexcept { return public_; }
    [[nodiscard]] const X25519Secret& secret_key()  const noexcept { return secret_; }

    static Result<X25519KeyPair> from_secret(ByteSpan secret);

private:
    X25519KeyPair() = default;

    X25519Public public_{};
    X25519Secret secret_;
};

Status verify_signature(
    ByteSpan message,
    const Signature& signature,
    const PublicKey& public_key
);

Result<SharedSecret> x25519_dh(
    const X25519Secret& our_secret,
    const X25519Public& their_public
);

Result<X25519Public> ed25519_pk_to_x25519(const PublicKey& ed_pk);

}