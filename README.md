# Poly1305ChaCha20.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Poly1305ChaCha20.NetCore.svg)](https://www.nuget.org/packages/Poly1305ChaCha20.NetCore/)

Implementation of poly1305-dona message authentication code, designed by D. J. Bernstein with a chacha20 nonce.  Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory) depends on [ChaCha20.NetCore](https://github.com/TimothyMeadows/ChaCha20.NetCore).

# Install

## Runtime

This project now targets **.NET 8** by default.

Nonce handling follows RFC 8439 expectations (96-bit nonce for ChaCha20 input).


From a command prompt
```bash
dotnet add package Poly1305ChaCha20.NetCore
```

```bash
Install-Package Poly1305ChaCha20.NetCore
```

You can also search for package via your nuget ui / website:

https://www.nuget.org/packages/Poly1305ChaCha20.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var iv = new byte[12];
var key = new byte[32];

RandomNumberGenerator.Fill(iv);
RandomNumberGenerator.Fill(key);

using var keyPin = new PinnedMemory<byte>(key, false);
using var cipher = new Poly1305ChaCha20(keyPin, iv);
var input = new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}; // caw caw caw in utf8
using var inputPin = new PinnedMemory<byte>(input, false);
cipher.UpdateBlock(inputPin, 0, input.Length);

using var output = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
cipher.DoFinal(output, 0);
```


# Constructor

```csharp
Poly1305ChaCha20(PinnedMemory<byte> key, byte[] nonce)
```

# Methods

Get the message digest output length.
```csharp
int GetLength()
```

Update the message digest with a single byte.
```csharp
void Update(byte input)
```

Update the message digest with a pinned memory byte array.
```csharp
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
```

Update the message digest with a byte array.
```csharp
void UpdateBlock(byte[] input, int inOff, int len)
```

Produce the final digest value outputting to pinned memory. Key and nonce-derived state remain until dispose is called.
```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```

Reset the digest back to it's initial state for further processing. Key and nonce-derived state remain until dispose is called.
```csharp
void Reset()
```

Clear key & salt, reset digest back to it's initial state.
```csharp
void Dispose()
```


## Security notes

- Never reuse the same `(key, nonce)` pair for different messages. Reuse breaks Poly1305 security guarantees.
- Nonces must be generated with a cryptographically secure RNG or from a monotonic counter scheme that never repeats per key.
- Dispose `Poly1305ChaCha20` and `PinnedMemory<byte>` instances promptly so sensitive material can be cleared from memory.

