<p align="center">
  <img src="assets/branding.svg" alt="shatters sdk" width="300"/>
</p>

<p align="center">
  <strong>C++23 cryptographic SDK for end-to-end encrypted messaging over QUIC.</strong>
</p>

<p align="center">
  <a href="#features">Features</a>
  <a href="#getting-started">Getting Started</a>
  <a href="#c-api">C API</a>
  <a href="#license">License</a>
</p>

---

Core library behind [Shatters](https://github.com/SuperpositionLabs/shatters). Implements X3DH key agreement, Double Ratchet with forward secrecy, encrypted local storage, and QUIC transport — all in a single static library.

## Features

| Feature | Description |
|---|---|
| **X3DH** | [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/) key agreement for session establishment |
| **Double Ratchet** | [Signal protocol](https://signal.org/docs/specifications/doubleratchet/) ratchet with forward and future secrecy |
| **QUIC Transport** | Low-latency multiplexed connections via [MsQuic](https://github.com/microsoft/msquic) with TLS 1.3 and certificate pinning |
| **Ed25519 Auth** | Per-connection authentication and channel-scoped proof signatures |
| **Dead Drop** | Encrypted mailboxes for async handshakes when the recipient is offline |
| **Encrypted Storage** | SQLite3 with XChaCha20-Poly1305 (Argon2id key derivation) |
| **Pub/Sub Messaging** | Real-time delivery over 32-byte channel identifiers |
| **C API** | `extern "C"` FFI surface (`shatters_c.h`) for bindings from Rust, Python, etc. |

## Getting Started

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| C++ compiler | GCC 13+, Clang 17+, or MSVC 17.6+ | Must support C++23 |
| CMake | ≥ 3.25 | |
| Ninja | any | Linux builds |
| vcpkg | included | Git submodule under `vcpkg/` |

### Build on Debian 13 (Trixie)

Install system dependencies:

```bash
sudo apt install -y \
  build-essential cmake ninja-build pkg-config git curl \
  libssl-dev
```

Bootstrap vcpkg and build:

```bash
git clone --recurse-submodules https://github.com/SuperpositionLabs/shatters-sdk.git
cd shatters-sdk

# bootstrap vcpkg (one-time)
./vcpkg/bootstrap-vcpkg.sh

# configure and build
cmake --preset linux-release
cmake --build build/linux-release

# run tests
ctest --preset linux-debug
```

### Build on Windows

```bash
cmake --preset windows-x64-release
cmake --build build/windows-x64-release --config Release
ctest --preset windows-debug
```

### CMake options

| Option | Default | Description |
|---|---|---|
| `SHATTERS_BUILD_TESTS` | `ON` | Build unit tests |
| `SHATTERS_BUILD_EXAMPLES` | `ON` | Build example programs |
| `SHATTERS_ASAN` | `OFF` | Address sanitizer |
| `SHATTERS_TSAN` | `OFF` | Thread sanitizer |

### Usage as a dependency

```cmake
find_package(shatters-sdk CONFIG REQUIRED)
target_link_libraries(myapp PRIVATE shatters::sdk)
```

## C API

The SDK exposes a complete `extern "C"` interface in [`shatters_c.h`](include/shatters/shatters_c.h) for use from other languages (Rust FFI, Python ctypes, etc.).

```c
#include <shatters/shatters_c.h>

ShattersClient* client = NULL;
ShattersStatus status = shatters_create(
    "shatters.db", "passphrase",
    "127.0.0.1", 4433,
    NULL, 0,       /* tls pin */
    1,             /* auto-reconnect */
    &client
);

if (status.code == SHATTERS_OK)
{
    shatters_connect(client);
    /* ... */
    shatters_destroy(client);
}
shatters_status_free(&status);
```

All returned strings and buffers are heap-allocated and must be freed with the corresponding `shatters_*_free()` function.

## Dependencies

Managed automatically by vcpkg:

| Library | Purpose |
|---|---|
| [libsodium](https://doc.libsodium.org/) | Ed25519, X25519, XChaCha20-Poly1305, Argon2id, HKDF |
| [MsQuic](https://github.com/microsoft/msquic) | QUIC transport with 0-RTT |
| [spdlog](https://github.com/gabime/spdlog) | Structured logging |
| [SQLite3](https://www.sqlite.org/) | Encrypted local storage |
| [GoogleTest](https://github.com/google/googletest) | Unit and integration testing |

## License

GPLv3 - see [LICENSE](LICENSE).
