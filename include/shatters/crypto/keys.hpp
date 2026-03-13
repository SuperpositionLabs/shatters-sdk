#pragma once

#include <shatters/crypto/secure_memory.hpp>
#include <shatters/constants.hpp>

namespace shatters::crypto {

using PublicKey  = ByteArray<kKeySize>;
using Signature  = ByteArray<kSignatureSize>;

struct SigningKeyPair {
    SecureArray<64> secret_key;   // Ed25519: seed || public
    PublicKey public_key;
};

struct DHKeyPair {
    SecureArray<kKeySize> secret_key;
    PublicKey public_key;
};

SigningKeyPair generate_signing_keypair();
DHKeyPair generate_dh_keypair();

Signature sign(const SecureArray<64>& secret_key,
               const uint8_t* message, size_t message_len);

bool verify(const PublicKey& public_key,
            const uint8_t* message, size_t message_len,
            const Signature& signature);

// X25519 Diffie-Hellman
SecureArray<kKeySize> dh(const SecureArray<kKeySize>& our_secret,
                         const PublicKey& their_public);

// Ed25519 <-> X25519 conversion
PublicKey ed25519_pk_to_x25519(const PublicKey& ed_pk);
SecureArray<kKeySize> ed25519_sk_to_x25519(const SecureArray<64>& ed_sk);

} // namespace shatters::crypto
