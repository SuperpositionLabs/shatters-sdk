#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <sodium.h>

namespace shatters::crypto {

// Public data (keys, hashes, signatures) — no special memory protection
template <size_t N>
using ByteArray = std::array<uint8_t, N>;

// Fixed-size secure array on stack. Zeroed via sodium_memzero on destruction.
// Move-only: copies are deleted to prevent accidental duplication of secrets.
template <size_t N>
class SecureArray {
    alignas(16) std::array<uint8_t, N> data_{};

public:
    SecureArray() = default;

    ~SecureArray() {
        sodium_memzero(data_.data(), N);
    }

    SecureArray(SecureArray&& other) noexcept : data_(other.data_) {
        sodium_memzero(other.data_.data(), N);
    }

    SecureArray& operator=(SecureArray&& other) noexcept {
        if (this != &other) {
            sodium_memzero(data_.data(), N);
            data_ = other.data_;
            sodium_memzero(other.data_.data(), N);
        }
        return *this;
    }

    SecureArray(const SecureArray&) = delete;
    SecureArray& operator=(const SecureArray&) = delete;

    uint8_t* data() noexcept { return data_.data(); }
    const uint8_t* data() const noexcept { return data_.data(); }
    static constexpr size_t size() noexcept { return N; }

    uint8_t& operator[](size_t i) noexcept { return data_[i]; }
    const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

    auto begin() noexcept { return data_.begin(); }
    auto end() noexcept { return data_.end(); }
    auto begin() const noexcept { return data_.begin(); }
    auto end() const noexcept { return data_.end(); }

    bool operator==(const SecureArray& other) const {
        return sodium_memcmp(data_.data(), other.data_.data(), N) == 0;
    }

    bool operator!=(const SecureArray& other) const {
        return !(*this == other);
    }
};

// Dynamic-size secure buffer on heap. Allocated via sodium_malloc (guard pages
// + mlock). Freed via sodium_free (memzero + munlock). Move-only.
class SecureBuffer {
    uint8_t* data_ = nullptr;
    size_t size_ = 0;

public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    uint8_t& operator[](size_t i) noexcept { return data_[i]; }
    const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

    uint8_t* begin() noexcept { return data_; }
    uint8_t* end() noexcept { return data_ + size_; }
    const uint8_t* begin() const noexcept { return data_; }
    const uint8_t* end() const noexcept { return data_ + size_; }
};

}
