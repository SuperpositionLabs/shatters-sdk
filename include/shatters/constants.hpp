#pragma once

#include <cstddef>
#include <cstdint>

namespace shatters {

inline constexpr size_t kKeySize          = 32;
inline constexpr size_t kSignatureSize    = 64;
inline constexpr size_t kAeadNonceSize    = 12;
inline constexpr size_t kAeadTagSize      = 16;
inline constexpr size_t kHashSize         = 32;
inline constexpr size_t kDeadDropIdSize   = 32;
inline constexpr size_t kDeviceIdSize     = 32;
inline constexpr size_t kFingerprintSize  = 20;
inline constexpr size_t kMaxBlobSize      = 32768;
inline constexpr size_t kMaxGroupSize     = 20;
inline constexpr size_t kPreKeyBatchSize  = 100;
inline constexpr size_t kMaxSkippedKeys   = 1000;
inline constexpr uint8_t kProtocolVersion = 0x01;

} // namespace shatters
