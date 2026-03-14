#include <shatters/crypto/aead.hpp>

#include <sodium.h>

#include <cstring>

namespace shatters::crypto
{

Result<Bytes> aead_encrypt(
    ByteSpan plaintext,
    ByteSpan ad,
    const AeadNonce& nonce,
    const AeadKey& key)
{
    Bytes ciphertext(plaintext.size() + AEAD_TAG_SIZE);
    unsigned long long clen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &clen,
            plaintext.data(), plaintext.size(),
            ad.data(), ad.size(),
            nullptr,
            nonce.data(),
            key.data()) != 0)
    {
        return Error{ErrorCode::CryptoError, "aead encryption failed"};
    }

    ciphertext.resize(static_cast<size_t>(clen));
    return ciphertext;
}

Result<Bytes> aead_decrypt(
    ByteSpan ciphertext,
    ByteSpan ad,
    const AeadNonce& nonce,
    const AeadKey& key)
{
    if (ciphertext.size() < AEAD_TAG_SIZE)
        return Error{ErrorCode::CryptoError, "ciphertext too short"};

    Bytes plaintext(ciphertext.size() - AEAD_TAG_SIZE);
    unsigned long long mlen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &mlen,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size(),
            nonce.data(),
            key.data()) != 0)
    {
        return Error{ErrorCode::CryptoError, "aead decryption failed (tampered or wrong key)"};
    }

    plaintext.resize(static_cast<size_t>(mlen));
    return plaintext;
}

Result<Bytes> aead_seal(ByteSpan plaintext, ByteSpan ad, const AeadKey& key)
{
    AeadNonce nonce = generate_nonce();

    auto ct = aead_encrypt(plaintext, ad, nonce, key);
    SHATTERS_TRY(ct);

    Bytes sealed;
    sealed.reserve(AEAD_NONCE_SIZE + ct.value().size());
    sealed.insert(sealed.end(), nonce.begin(), nonce.end());
    sealed.insert(sealed.end(), ct.value().begin(), ct.value().end());

    return sealed;
}

Result<Bytes> aead_open(ByteSpan sealed, ByteSpan ad, const AeadKey& key)
{
    if (sealed.size() < AEAD_NONCE_SIZE + AEAD_TAG_SIZE)
        return Error{ErrorCode::CryptoError, "sealed data too short"};

    AeadNonce nonce{};
    std::memcpy(nonce.data(), sealed.data(), AEAD_NONCE_SIZE);

    const ByteSpan ciphertext{sealed.data() + AEAD_NONCE_SIZE, sealed.size() - AEAD_NONCE_SIZE};
    return aead_decrypt(ciphertext, ad, nonce, key);
}

AeadNonce generate_nonce()
{
    AeadNonce nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

AeadNonce nonce_from_counter(uint32_t counter)
{
    AeadNonce nonce{};
    nonce[20] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    nonce[21] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    nonce[22] = static_cast<uint8_t>((counter >>  8) & 0xFF);
    nonce[23] = static_cast<uint8_t>( counter        & 0xFF);
    return nonce;
}

}