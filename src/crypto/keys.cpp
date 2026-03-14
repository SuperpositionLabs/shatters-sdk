#include <shatters/crypto/keys.hpp>

#include <sodium.h>

#include <cstring>

namespace shatters::crypto
{

template <size_t N>
SecureBuffer<N>::~SecureBuffer() noexcept
{
    sodium_memzero(data_.data(), N);
}

template <size_t N>
SecureBuffer<N>::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_)
{
    sodium_memzero(other.data_.data(), N);
}

template <size_t N>
SecureBuffer<N>& SecureBuffer<N>::operator=(SecureBuffer&& other) noexcept
{
    if (this != &other)
    {
        sodium_memzero(data_.data(), N);
        data_ = other.data_;
        sodium_memzero(other.data_.data(), N);
    }
    return *this;
}

template class SecureBuffer<ED25519_SECRET_KEY_SIZE>;
template class SecureBuffer<ED25519_SEED_SIZE>;
template class SecureBuffer<X25519_KEY_SIZE>;
template class SecureBuffer<X25519_SHARED_SIZE>;

Result<IdentityKeyPair> IdentityKeyPair::generate()
{
    IdentityKeyPair kp;

    crypto_sign_ed25519_keypair(kp.ed_public_.data(), kp.ed_secret_.data());

    SHATTERS_TRY(kp.derive_x25519());
    return kp;
}

Result<IdentityKeyPair> IdentityKeyPair::from_seed(ByteSpan seed)
{
    if (seed.size() != ED25519_SEED_SIZE)
        return Error{ErrorCode::InvalidArgument, "seed must be 32 bytes"};

    IdentityKeyPair kp;

    crypto_sign_ed25519_seed_keypair(
        kp.ed_public_.data(),
        kp.ed_secret_.data(),
        seed.data()
    );
    SHATTERS_TRY(kp.derive_x25519());

    return kp;
}

Status IdentityKeyPair::derive_x25519()
{
    if (crypto_sign_ed25519_pk_to_curve25519(x_public_.data(), ed_public_.data()) != 0)
        return Error{ErrorCode::CryptoError, "ed25519 pk to x25519 conversion failed"};

    if (crypto_sign_ed25519_sk_to_curve25519(x_secret_.data(), ed_secret_.data()) != 0)
        return Error{ErrorCode::CryptoError, "ed25519 sk to x25519 conversion failed"};

    return {};
}

Result<Signature> IdentityKeyPair::sign(ByteSpan message) const
{
    Signature sig{};
    crypto_sign_ed25519_detached(
        sig.data(), nullptr,
        message.data(), message.size(),
        ed_secret_.data()
    );
    return sig;
}

Seed IdentityKeyPair::seed() const
{
    Seed s;
    crypto_sign_ed25519_sk_to_seed(s.data(), ed_secret_.data());
    return s;
}

Result<X25519KeyPair> X25519KeyPair::generate()
{
    X25519KeyPair kp;

    randombytes_buf(kp.secret_.data(), X25519_KEY_SIZE);
    crypto_scalarmult_base(kp.public_.data(), kp.secret_.data());

    return kp;
}

Result<X25519KeyPair> X25519KeyPair::from_secret(ByteSpan secret)
{
    if (secret.size() != X25519_KEY_SIZE)
        return Error{ErrorCode::InvalidArgument, "x25519 secret key must be 32 bytes"};

    X25519KeyPair kp;
    std::memcpy(kp.secret_.data(), secret.data(), X25519_KEY_SIZE);
    crypto_scalarmult_base(kp.public_.data(), kp.secret_.data());

    return kp;
}

Status verify_signature(
    ByteSpan message,
    const Signature& signature,
    const PublicKey& public_key)
{
    if (crypto_sign_ed25519_verify_detached(
            signature.data(),
            message.data(), message.size(),
            public_key.data()) != 0)
    {
        return Error{ErrorCode::CryptoError, "signature verification failed"};
    }
    return {};
}

Result<SharedSecret> x25519_dh(
    const X25519Secret& our_secret,
    const X25519Public& their_public)
{
    SharedSecret shared;

    if (crypto_scalarmult(shared.data(), our_secret.data(), their_public.data()) != 0)
        return Error{ErrorCode::CryptoError, "x25519 dh failed (low-order point)"};

    return shared;
}

Result<X25519Public> ed25519_pk_to_x25519(const PublicKey& ed_pk)
{
    X25519Public x_pk{};

    if (crypto_sign_ed25519_pk_to_curve25519(x_pk.data(), ed_pk.data()) != 0)
        return Error{ErrorCode::CryptoError, "ed25519 pk to x25519 conversion failed"};

    return x_pk;
}

}