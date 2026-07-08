# Mrbr.Service.EncryptionManager

`Mrbr.Service.EncryptionManager` provides usage-agnostic cryptographic services for .NET. It performs cryptographic actions only and leaves caller-specific workflows outside this package.

## Current Milestone

Implemented:

- AES-GCM encryption and decryption
- AES-128, AES-192, and AES-256 key sizes
- SHA-256, SHA-384, and SHA-512 hashing
- HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 message authentication
- Constructor-injected `IKeyService` from `Mrbr.Service.KeyManager`
- Byte-first APIs with UTF-8 string convenience wrappers
- Typed artifact serializers for common binary and text shapes

Planned:

- Signing helper methods over appropriate cryptographic primitives
- Asymmetric signatures
- Post-quantum cryptographic operations

## KeyManager Relationship

EncryptionManager does not create or manage key sources. Operations that need key material request it from an injected `IKeyService`.

`KeyHandle` values are `ulong`. Encryption and HMAC operations return the `KeyHandle` alongside the generated artifact so callers can replay the same key material through KeyManager during decryption or validation.

Consumers must register `IKeyService` separately before registering EncryptionManager services.

## Dependency Injection

If you are using KeyManager's `WebApplicationBuilder` helper, register KeyManager first and then EncryptionManager:

```csharp
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.KeyManager.Configuration;

builder.ConfigureKeyService();
builder.Services.AddEncryptionManager();
```

The equivalent service registrations are:

```csharp
using Microsoft.Extensions.DependencyInjection;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;

services.Configure<KeyServiceConfig>(configuration.GetSection(nameof(KeyService)));
services.AddSingleton<KeyServiceOptions>();
services.AddSingleton<IKeyService, KeyService>();

services.AddEncryptionManager();
```

`AddEncryptionManager()` registers EncryptionManager services only. It expects KeyManager's singleton `IKeyService` registration. If `IKeyService` is missing, resolving or running an operation that needs key material fails clearly through DI or constructor validation.

## AES-GCM Artifacts

AES-GCM artifacts are byte arrays with this layout:

```text
nonce[12] + tag[16] + ciphertext
```

The artifact does not include algorithm metadata. Callers select the algorithm through `EncryptionOptions` when encrypting or decrypting.

`EncryptionResult` returns:

```csharp
public sealed record EncryptionResult(ulong KeyHandle, byte[] Cipher);
```

## Basic Usage

```csharp
using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.EncryptionManager.Services;

var encryption = provider.GetRequiredService<ICryptographicService>();

byte[] plainText = "sensitive payload"u8.ToArray();
var options = new EncryptionOptions {
    Algorithm = SymmetricEncryptionAlgorithms.AES256
};

EncryptionResult encrypted = encryption.Encrypt(plainText, options);
byte[] decrypted = encryption.Decrypt(encrypted.KeyHandle, encrypted.Cipher, options);
```

Span overloads are available for callers that want to provide their own buffers:

```csharp
byte[] cipher = new byte[CryptographicService.GetCipherLength(plainText.Length)];
int cipherLength = encryption.Encrypt(plainText, cipher, out ulong keyHandle, options);

byte[] decrypted = new byte[plainText.Length];
int plainTextLength = encryption.Decrypt(keyHandle, cipher.AsSpan(0, cipherLength), decrypted, options);
```

String helpers wrap the byte API with UTF-8 encoding and return `{handle}:{Base64(artifact)}`.

## Hashing

Unkeyed hashes return only the hash bytes:

```csharp
var hashOptions = new HashOptions {
    Algorithm = HashingAlgorithms.SHA256
};

HashResult hash = cryptographicService.Hash(data, hashOptions);
bool valid = cryptographicService.ValidateHash(data, hash.Hash, hashOptions);
```

## HMAC

HMAC operations use KeyManager material and return a replay handle:

```csharp
var hmacOptions = new HmacOptions {
    Algorithm = HmacAlgorithms.HMACSHA256
};

HmacResult hmac = cryptographicService.Hmac(data, hmacOptions);
bool valid = cryptographicService.ValidateHmac(
    hmac.KeyHandle,
    data,
    hmac.Hmac,
    hmacOptions);
```

`HmacOptions.KeySizeInBits` controls HMAC key material size. Supported key sizes are 128, 192, and 256 bits; the default is 256 bits. HMAC operations authenticate exactly the bytes supplied by the caller; the `KeyHandle` is returned as replay metadata.

## Artifact Serializers

`CryptographicArtifactSerializer` provides helpers for common shapes:

- `{artifact}` as raw bytes
- `{Base64(artifact)}`
- `{handle}:{artifact}` as ASCII handle prefix plus raw artifact bytes
- `{handle}:{Base64(artifact)}`
- `{Hex(artifact)}`
- `{handle}:{Hex(artifact)}`

For result-specific helpers, use the extension methods on `EncryptionResult` and `HmacResult`:

```csharp
string cipherPayload = encrypted.ToKeyHandleCipherBase64();
string hmacPayload = hmac.ToKeyHandleHmacBase64();

byte[] rawCipher = encrypted.ToArtifactBytes(CryptographicArtifactFormat.Raw);
string hmacHex = hmac.ToArtifactText(CryptographicArtifactFormat.KeyHandleHex);
```

For callers that want separate fields, use the structured result objects directly or convert them to `KeyedCryptographicArtifact` with `ToKeyedArtifact()`.

## Associated Data

`EncryptionOptions.AssociatedData` is authenticated by AES-GCM but is not included in the artifact. The `KeyHandle` is also bound into AES-GCM associated data internally, so a different handle cannot validate the same artifact.

## Algorithm Status

`SymmetricEncryptionAlgorithms.AES128`, `AES192`, and `AES256` are implemented through AES-GCM.

`HashingAlgorithms.SHA256`, `SHA384`, and `SHA512` are implemented for unkeyed hashing. Other `HashingAlgorithms` values are declared but not implemented.

`HmacAlgorithms.HMACSHA256`, `HMACSHA384`, and `HMACSHA512` are implemented for keyed message authentication.

`AsymmetricAlgorithms` currently declares planned asymmetric signature and encryption surfaces. They are not implemented yet.

## Build And Test

```bash
dotnet build Mrbr.Service.EncryptionManager.slnx
dotnet test Mrbr.Service.EncryptionManager.slnx
```

## Requirements

- .NET 11.0 or higher
- `Mrbr.Service.KeyManager` 1.0.2 or higher
