# Poly1305ChaCha20.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![nuget](https://img.shields.io/nuget/v/Poly1305ChaCha20.NetCore.svg)](https://www.nuget.org/packages/Poly1305ChaCha20.NetCore/)

`Poly1305ChaCha20.NetCore` is a .NET implementation of Poly1305 message authentication using a ChaCha20-derived one-time pad key stream.

The library is designed around:

- **Poly1305 authenticator** with 128-bit output (16-byte tag)
- **ChaCha20 nonce-based key derivation** with RFC 8439-style 96-bit nonce handling
- **`PinnedMemory` integration** for security-conscious memory handling

This implementation is based on the `poly1305-donna` approach and is adapted from the BouncyCastle Poly1305 implementation.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API reference](#api-reference)
  - [`Poly1305ChaCha20`](#poly1305chacha20)
- [Usage notes and best practices](#usage-notes-and-best-practices)
- [Validation and known vectors](#validation-and-known-vectors)
- [Development](#development)
- [Security notes](#security-notes)
- [License](#license)

---

## Requirements

- **.NET 8 SDK** for building and testing this repository.
- Project target framework: **.NET 8**.

The repository includes a `global.json` to pin the SDK family used during development.

---

## Installation

### NuGet Package Manager (CLI)

```bash
dotnet add package Poly1305ChaCha20.NetCore
```

### Package Manager Console

```powershell
Install-Package Poly1305ChaCha20.NetCore
```

### NuGet Gallery

- https://www.nuget.org/packages/Poly1305ChaCha20.NetCore/

---

## Quick start

```csharp
using System;
using System.Security.Cryptography;
using Poly1305ChaCha20.NetCore;
using PinnedMemory;

var nonce = new byte[12];  // 96-bit nonce
var key = new byte[32];    // 256-bit key

RandomNumberGenerator.Fill(nonce);
RandomNumberGenerator.Fill(key);

var message = new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 };

using var keyPin = new PinnedMemory<byte>(key, false);
using var poly = new Poly1305ChaCha20(keyPin, nonce);

poly.UpdateBlock(message, 0, message.Length);

using var tag = new PinnedMemory<byte>(new byte[poly.GetLength()]);
poly.DoFinal(tag, 0);

Console.WriteLine(Convert.ToHexString(tag.ToArray()).ToLowerInvariant());
```

---

## API reference

## `Poly1305ChaCha20`

### Constructor

```csharp
Poly1305ChaCha20(PinnedMemory<byte> key, byte[] nonce)
```

- `key` must be exactly **32 bytes** (256-bit).
- `nonce` must be exactly **12 bytes** (96-bit, RFC 8439).

### Core methods

```csharp
int GetLength()
void Update(byte input)
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
void UpdateBlock(byte[] input, int inOff, int len)
void DoFinal(PinnedMemory<byte> output, int outOff)
void Reset()
void Dispose()
```

### Behavior notes

- `GetLength()` always returns **16** bytes.
- `DoFinal(...)` finalizes the MAC and resets internal accumulator state for reuse with the same key/nonce-derived state.
- Calling `Dispose()` clears key-derived and internal state.

---

## Usage notes and best practices

1. **Never reuse the same `(key, nonce)` pair for different messages.**
   Reuse breaks Poly1305 security guarantees.

2. **Use CSPRNG or strict monotonic nonce strategy.**
   Nonces must be unique per key.

3. **Use explicit message framing in protocols.**
   MAC only the exact bytes expected by both producer and consumer.

4. **Prefer chunked updates for large payloads.**
   Feed data via repeated `UpdateBlock(...)` calls rather than buffering entire files in memory.

5. **Dispose sensitive objects promptly.**
   Dispose `Poly1305ChaCha20` and pinned key buffers as soon as they are no longer needed.

---

## Validation and known vectors

The test suite includes RFC 8439-aligned fixtures and behavior checks, including:

- AEAD Poly1305 input construction based on RFC 8439 section 2.8.2.
- Empty-message tag derivation with RFC key/nonce pair.
- Equivalence between single-byte streaming (`Update`) and bulk updates (`UpdateBlock`).

Current expected tags in the tests include:

- AEAD sample MAC data tag:
  `7a89db1fa35355e01edb7cec09cef46e`
- Empty-message tag with the same RFC key/nonce pair:
  `bdf04aa919d52933ae8675e94f166299`

---

## Development

### Build

```bash
dotnet build Poly1305ChaCha20.NetCore.sln
```

### Test

```bash
dotnet test Poly1305ChaCha20.NetCore.sln
```

---

## Security notes

- This library provides **message authentication** (MAC), not encryption.
- Keep secret keys out of logs, telemetry, and crash dumps.
- Ensure nonce uniqueness per key at the application/protocol level.
- Treat produced MAC tags as authenticity checks only; they do not hide plaintext.

---

## License

This project is licensed under the MIT License.
