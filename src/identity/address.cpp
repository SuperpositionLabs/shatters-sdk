#include <shatters/identity/address.hpp>

#include <sodium.h>

#include <cstring>

namespace shatters::identity
{

static constexpr char BASE32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static std::string base32_encode(const uint8_t* data, size_t len)
{
    std::string result;
    result.reserve((len * 8 + 4) / 5);

    uint64_t buffer = 0;
    int bits = 0;

    for (size_t i = 0; i < len; ++i)
    {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            result += BASE32_ALPHABET[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0)
    {
        result += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1F];
    }

    return result;
}

static int base32_decode_char(char c)
{
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static bool base32_decode(const std::string& input, uint8_t* output, size_t output_len)
{
    uint64_t buffer = 0;
    int bits = 0;
    size_t pos = 0;

    for (char c : input)
    {
        int val = base32_decode_char(c);
        if (val < 0) return false;

        buffer = (buffer << 5) | static_cast<uint64_t>(val);
        bits += 5;

        if (bits >= 8)
        {
            bits -= 8;
            if (pos >= output_len) return false;
            output[pos++] = static_cast<uint8_t>((buffer >> bits) & 0xFF);
        }
    }

    return pos == output_len;
}

ContactAddress ContactAddress::from_public_key(const crypto::PublicKey& public_key)
{
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, public_key.data(), public_key.size());

    ContactAddress addr;
    addr.raw_[0] = 0x00; 
    std::memcpy(addr.raw_.data() + 1, hash, HASH_TRUNCATED_SIZE);

    unsigned char checksum_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(checksum_hash, addr.raw_.data(), 1 + HASH_TRUNCATED_SIZE);
    addr.raw_[1 + HASH_TRUNCATED_SIZE]     = checksum_hash[0];
    addr.raw_[1 + HASH_TRUNCATED_SIZE + 1] = checksum_hash[1];

    addr.address_str_ = base32_encode(addr.raw_.data(), addr.raw_.size());
    return addr;
}

Result<ContactAddress> ContactAddress::from_string(const std::string& address_str)
{
    ContactAddress addr;

    if (!base32_decode(address_str, addr.raw_.data(), addr.raw_.size()))
        return Error{ErrorCode::InvalidArgument, "invalid contact address encoding"};

    if (addr.raw_[0] != 0x00)
        return Error{ErrorCode::InvalidArgument, "unsupported address version"};

    unsigned char checksum_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(checksum_hash, addr.raw_.data(), 1 + HASH_TRUNCATED_SIZE);

    if (addr.raw_[1 + HASH_TRUNCATED_SIZE]     != checksum_hash[0] ||
        addr.raw_[1 + HASH_TRUNCATED_SIZE + 1] != checksum_hash[1])
    {
        return Error{ErrorCode::InvalidArgument, "contact address checksum mismatch"};
    }

    addr.address_str_ = address_str;
    for (auto& c : addr.address_str_)
    {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }

    return addr;
}

Channel ContactAddress::intro_channel() const
{
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state,
        reinterpret_cast<const unsigned char*>(address_str_.data()),
        address_str_.size()
    );

    static constexpr std::string_view suffix = "intro";
    crypto_hash_sha256_update(&state,
        reinterpret_cast<const unsigned char*>(suffix.data()),
        suffix.size()
    );

    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&state, hash);

    Channel ch{};
    std::memcpy(ch.data(), hash, CHANNEL_SIZE);
    return ch;
}

}