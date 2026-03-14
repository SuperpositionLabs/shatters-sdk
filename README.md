<p align="center">
  <img src="assets/branding.svg" alt="shatters logo" width="300"/>
</p>

<p align="center">
  C++23 cryptographic SDK powering end-to-end encrypted messaging over QUIC.
</p>

<p align="center">
  <a href="#features">Features</a> &middot;
  <a href="#wire-protocol">Protocol</a> &middot;
  <a href="#building">Building</a> &middot;
  <a href="#usage">Usage</a> &middot;
  <a href="#license">License</a>
</p>

---

The core library behind shatters, a private, encrypted communication system. No third parties. No data collection.

## Features

- **QUIC transport** via [MsQuic](https://github.com/microsoft/msquic)
- **Dead Drop mailboxes** one-time-use encrypted mailboxes

## Wire Protocol

All messages use a fixed binary format with no string identifiers on the wire.

### Layout

```
---------------------------------------------------------
| type (1) | id (4 BE) | channel (32) | payload (var)   |
---------------------------------------------------------
```

Minimum message size: **37 bytes** (header only, no payload).

### Types

| Type | Value | Direction | Description |
|---|---|---|---|
| `Publish` | `0x01` | Client -> Relay | Publish payload to a channel |
| `Subscribe` | `0x02` | Client -> Relay | Subscribe to a channel |
| `Unsubscribe` | `0x03` | Client -> Relay | Unsubscribe from a channel |
| `Retrieve` | `0x04` | Client -> Relay | Retrieve dead-drop envelope |
| `Ack` | `0x10` | Relay -> Client | Operation succeeded |
| `Nack` | `0x11` | Relay -> Client | Operation failed |
| `Data` | `0x20` | Relay -> Client | Incoming message for a subscribed channel |

### Framing

Messages are length-prefixed before transmission:

```
--------------------------------------------
| length (4 BE)      │ message (length)    |
--------------------------------------------
```

- 4-byte big-endian length prefix
- maximum frame size: **1 MiB**
- ALPN: `$hatter$/1`

## Building

### Dependencies

| Library | Purpose |
|---|---|
| [libsodium](https://doc.libsodium.org/) | Cryptographic primitives, hashing, TLS pin verification |
| [MsQuic](https://github.com/microsoft/msquic) | QUIC transport |
| [spdlog](https://github.com/gabime/spdlog) | Structured logging |
| [SQLite3](https://www.sqlite.org/) | Local persistence |
| [GoogleTest](https://github.com/google/googletest) | Unit testing framework |

### Steps

```bash
# clone with submodules
git clone --recurse-submodules <repo-url>
cd shatters-sdk

# configure (picks vcpkg automatically)
cmake --preset windows-x64-release    # or linux-release

# build
cmake --build build/windows-x64-release --config Release

# run tests
ctest --preset windows-x64-release
```

### Available Presets

| Preset | Platform | Generator |
|---|---|---|
| `windows-x64-debug` | Windows | Visual Studio |
| `windows-x64-release` | Windows | Visual Studio |
| `linux-debug` | Linux | Ninja |
| `linux-release` | Linux | Ninja |

### CMake Options

| Option | Default | Description |
|---|---|---|
| `SHATTERS_BUILD_TESTS` | `ON` | Build unit tests |
| `SHATTERS_BUILD_EXAMPLES` | `ON` | Build example programs |
| `SHATTERS_ASAN` | `OFF` | Enable AddressSanitizer |
| `SHATTERS_TSAN` | `OFF` | Enable ThreadSanitizer |

## Usage

A full working chat application is provided in [`examples/chat.cpp`](examples/chat.cpp):

```bash
# terminal 1
./chat alice 127.0.0.1 4433 lobby

# terminal 2
./chat bob 127.0.0.1 4433 lobby
```


## License

GNU GPLv3 - see [LICENSE](LICENSE).
