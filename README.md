<p align="center">
  <img src="assets/branding.svg" alt="shatters logo" width="300"/>
</p>

<p align="center">
  <strong>C++23 cryptographic SDK for end-to-end encrypted messaging over QUIC.</strong>
</p>

<p align="center">
  <a href="#features">Features</a> &middot;
  <a href="#getting-started">Getting Started</a> &middot;
  <a href="#license">License</a>
</p>

---

The core library behind shatters, a private, encrypted communication system. No third parties. No data collection. No compromises.

## Features

- **QUIC**: low-latency, multiplexed connections via [MsQuic](https://github.com/microsoft/msquic) with TLS 1.3 and pinning
- **E2EE**: [X3DH](https://signal.org/docs/specifications/x3dh/) key agreement + [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) with forward and backward secrecy
- **Dead Drop**: one-time-use, TTL-enforced encrypted mailboxes for async handshakes
- **Pub/Sub Messaging**: real-time message delivery over 32-byte channels
- **Encrypted Storage**: SQLite3 with XChaCha20-Poly1305 and Argon2id
- **Contact Management**: persistent contact list with public key verification
- **Secure by Design**: memory-safe C++23, libsodium primitives, secure key handling, and comprehensive errors

## Getting Started

### Prerequisites

- **C++23** compatible compiler (MSVC 17.6+, GCC 13+, Clang 17+)
- **CMake** 3.25+
- **vcpkg** (included as a submodule)

### Dependencies

All dependencies are managed automatically through vcpkg:

| Library | Purpose |
|---|---|
| [libsodium](https://doc.libsodium.org/) | Cryptographic primitives |
| [MsQuic](https://github.com/microsoft/msquic) | QUIC transport |
| [spdlog](https://github.com/gabime/spdlog) | Structured logging |
| [SQLite3](https://www.sqlite.org/) | Local persistence |
| [GoogleTest](https://github.com/google/googletest) | Unit and integration testing |

### Build

```bash
# clone with submodules (includes vcpkg)
git clone --recurse-submodules <repo-url>
cd shatters-sdk

# configure
cmake --preset windows-x64-release    # or linux-release

# build the library and examples
cmake --build build/windows-x64-release --config Release

# run tests
ctest --preset windows-x64-release
```

### Build Presets

| Preset | Platform | Generator |
|---|---|---|
| `windows-x64-debug` | Windows | Visual Studio 17 |
| `windows-x64-release` | Windows | Visual Studio 17 |
| `linux-debug` | Linux | Ninja |
| `linux-release` | Linux | Ninja |

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
