#include <shatters/crypto/keys.hpp>
#include <sodium.h>
#include <stdexcept>

namespace shatters::crypto {

SigningKeyPair generate_signing_keypair() {
    SigningKeyPair kp;
    crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

DHKeyPair generate_dh_keypair() {
    DHKeyPair kp;
    crypto_box_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

Signature sign(const SecureArray<64>& secret_key,
               const uint8_t* message, size_t message_len) {
    Signature sig;
    crypto_sign_detached(sig.data(), nullptr,
                         message, message_len,
                         secret_key.data());
    return sig;
}

bool verify(const PublicKey& public_key,
            const uint8_t* message, size_t message_len,
            const Signature& signature) {
    return crypto_sign_verify_detached(
        signature.data(), message, message_len, public_key.data()) == 0;
}

SecureArray<kKeySize> dh(const SecureArray<kKeySize>& our_secret,
                         const PublicKey& their_public) {
    SecureArray<kKeySize> shared;
    if (crypto_scalarmult(shared.data(), our_secret.data(), their_public.data()) != 0) {
        throw std::runtime_error("DH computation failed (low-order point)");
    }
    return shared;
}

PublicKey ed25519_pk_to_x25519(const PublicKey& ed_pk) {
    PublicKey x_pk;
    if (crypto_sign_ed25519_pk_to_curve25519(x_pk.data(), ed_pk.data()) != 0) {
        throw std::runtime_error("Ed25519->X25519 public key conversion failed");
    }
    return x_pk;
}

SecureArray<kKeySize> ed25519_sk_to_x25519(const SecureArray<64>& ed_sk) {
    SecureArray<kKeySize> x_sk;
    if (crypto_sign_ed25519_sk_to_curve25519(x_sk.data(), ed_sk.data()) != 0) {
        throw std::runtime_error("Ed25519->X25519 secret key conversion failed");
    }
    return x_sk;
}

} // namespace shatters::crypto
