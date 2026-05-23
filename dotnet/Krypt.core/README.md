# Krypt

**Krypt** is a .NET library for encryption and decryption of data. It provides a simple and secure way to protect sensitive information in your applications.

[![NuGet](https://img.shields.io/nuget/v/Krypt.Core.png)](https://www.nuget.org/packages/Krypt.Core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8%2B-512BD4)](https://dotnet.microsoft.com)

---

## Features

- AES-256-CBC encryption with automatic IV generation
- Key derivation from any passphrase via SHA-256
- Multiple overloads: `string`, `byte[]`, and `Stream` (sync + async)
- IV prepended to cipher output — no extra plumbing needed
- Zero dependencies beyond the .NET BCL

---

## Installation

```shell
dotnet add package Krypt.Core
```

---

## Quick Start

### Encrypt & decrypt a string

```csharp
using Krypt;

string secretKey = "secretkey123";
string toEncrypt = "Hello World!";

string encrypted = Krypt.Encryption.KryptAes.Encrypt(toEncrypt, secretKey);
Console.WriteLine($"Encrypted: {encrypted}");

string decrypted = Krypt.Encryption.KryptAes.Decrypt(encrypted, secretKey);
Console.WriteLine($"Decrypted: {decrypted}");
// Output:
// Encrypted: <base64 cipher>
// Decrypted: Hello World!
```

### Encrypt & decrypt raw bytes

```csharp
using Krypt.Encryption;

byte[] data   = File.ReadAllBytes("document.pdf");
byte[] cipher = KryptAes.Encrypt(data, "my-secret-passphrase");
byte[] plain  = KryptAes.Decrypt(cipher, "my-secret-passphrase");
```

### Encrypt & decrypt a file (stream)

```csharp
using Krypt.Encryption;

using FileStream input  = File.OpenRead("video.mp4");
using FileStream output = File.Create("video.mp4.enc");

KryptAes.Encrypt(input, output, "my-secret-passphrase");
```

```csharp
using FileStream cipher   = File.OpenRead("video.mp4.enc");
using FileStream restored = File.Create("video_restored.mp4");

KryptAes.Decrypt(cipher, restored, "my-secret-passphrase");
```

### Async stream (recommended for large files / web apps)

```csharp
await KryptAes.EncryptAsync(inputStream, outputStream, "my-secret-passphrase", cancellationToken);
await KryptAes.DecryptAsync(cipherStream, outputStream, "my-secret-passphrase", cancellationToken);
```

---

## API Reference

| Method | Description |
|--------|-------------|
| `Encrypt(string, string) → string` | Encrypts a UTF-8 string; returns Base-64 cipher |
| `Decrypt(string, string) → string` | Decrypts a Base-64 cipher; returns UTF-8 string |
| `Encrypt(byte[], string) → byte[]` | Encrypts raw bytes |
| `Decrypt(byte[], string) → byte[]` | Decrypts raw bytes |
| `Encrypt(Stream, Stream, string)` | Stream encryption (sync) |
| `Decrypt(Stream, Stream, string)` | Stream decryption (sync) |
| `EncryptAsync(Stream, Stream, string, CancellationToken)` | Stream encryption (async) |
| `DecryptAsync(Stream, Stream, string, CancellationToken)` | Stream decryption (async) |

---

## Technical Details

| Property | Value |
|----------|-------|
| Algorithm | AES |
| Key size | 256 bits |
| Mode | CBC |
| Padding | PKCS7 |
| IV size | 16 bytes (prepended to cipher output) |
| Key derivation | SHA-256 over the passphrase (UTF-8) |

The IV is randomly generated on every `Encrypt` call and prepended to the output. `Decrypt` strips it automatically — you never need to manage the IV yourself.

> **Note:** Key derivation uses a single SHA-256 pass for performance and portability. If you need stronger key stretching for user-facing passwords, consider pre-deriving your key with PBKDF2 or Argon2 before passing it to Krypt.

---

## Requirements

- .NET 8 or later

---

## License

[MIT](LICENSE)