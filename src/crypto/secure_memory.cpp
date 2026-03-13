#include <shatters/crypto/secure_memory.hpp>

#include <new>
#include <utility>

namespace shatters::crypto {

SecureBuffer::SecureBuffer(size_t size)
    : data_(static_cast<uint8_t*>(sodium_malloc(size)))
    , size_(size) {
    if (!data_) {
        throw std::bad_alloc();
    }
}

SecureBuffer::~SecureBuffer() {
    if (data_) {
        sodium_free(data_);
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(std::exchange(other.data_, nullptr))
    , size_(std::exchange(other.size_, 0)) {}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) {
            sodium_free(data_);
        }
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}
}
