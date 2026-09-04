# Mrbr.Service.EncryptionManager

`Mrbr.Service.EncryptionManager` provides usage-agnostic cryptographic services for .NET. It performs cryptographic actions only and leaves caller-specific workflows outside this package.

## Current Milestone

Implemented:

- AES-GCM encryption and decryption
- AES-128, AES-192, and AES-256 key sizes
- SHA-256, SHA-384, and SHA-512 hashing
- SHA-3-224/256/384/512 and SHAKE128/256 hashing
- HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 message authentication
- ML-KEM-512/768/1024 hybrid data protection with AES-256-GCM
- ML-DSA-44/65/87 signatures
- Automatic native .NET PQC selection with bundled Bouncy Castle fallback
- Constructor-injected `IKeyService` from `Mrbr.Service.KeyManager`
- Byte-first APIs with UTF-8 string convenience wrappers
- Typed artifact serializers for common binary and text shapes

Planned next: classical public-key encryption and signatures, consistent result-based failure APIs, and later PQC algorithms such as SLH-DSA.

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
byte keySourceId = GetKeySourceIdFromValidatedDeploymentConfiguration();

byte[] plainText = "sensitive payload"u8.ToArray();
var options = new EncryptionOptions {
    Algorithm = SymmetricEncryptionAlgorithms.AES256
};

EncryptionResult encrypted = encryption.Encrypt(keySourceId, plainText, options);
byte[] decrypted = encryption.Decrypt(encrypted.KeyHandle, encrypted.Cipher, options);
```

Span overloads are available for callers that want to provide their own buffers:

```csharp
byte[] cipher = new byte[CryptographicService.GetCipherLength(plainText.Length)];
int cipherLength = encryption.Encrypt(keySourceId, plainText, cipher, out ulong keyHandle, options);

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

SHAKE requires an explicit output length:

```csharp
var shakeOptions = new HashOptions {
    Algorithm = HashingAlgorithms.SHAKE256,
    OutputLengthInBytes = 64
};
```

## Post-quantum protection and signatures

PQC algorithms are explicit, but provider selection is automatic. The library uses native .NET support when available and otherwise uses its bundled Bouncy Castle dependency. No provider setting is required or persisted.

```csharp
var kemOptions = new PostQuantumEncryptionOptions(MlKemAlgorithms.MLKEM768);
EncryptionResult protectedData = cryptographicService.EncryptPostQuantum(keySourceId, data, kemOptions);
byte[] recovered = cryptographicService.DecryptPostQuantum(protectedData.KeyHandle, protectedData.Cipher, kemOptions);

var signatureOptions = new PostQuantumSignatureOptions(MlDsaAlgorithms.MLDSA65);
SignatureResult signature = cryptographicService.SignPostQuantum(keySourceId, data, signatureOptions);
bool signatureValid = cryptographicService.VerifyPostQuantum(signature.KeyHandle, data, signature.Signature, signatureOptions);
```

The ML-KEM artifact is opaque to callers. It contains the KEM output and AES-GCM protected datum; only the KeyManager handle is exposed separately. Use `PostQuantumAlgorithmInfo` for algorithm-specific storage sizing without parsing the artifact.

## HMAC

HMAC operations use KeyManager material and return a replay handle:

```csharp
var hmacOptions = new HmacOptions {
    Algorithm = HmacAlgorithms.HMACSHA256
};

HmacResult hmac = cryptographicService.Hmac(keySourceId, data, hmacOptions);
bool valid = cryptographicService.ValidateHmac(
    hmac.KeyHandle,
    data,
    hmac.Hmac,
    hmacOptions);
```

`HmacOptions.KeySizeInBits` controls HMAC key material size. Supported key sizes are 128, 192, and 256 bits; the default is 256 bits. HMAC operations authenticate exactly the bytes supplied by the caller; the `KeyHandle` is returned as replay metadata.

For deterministic keyed operations such as database equality-search tokens, provision one key handle outside the runtime data path and store that handle in deployment configuration. Replay it for every value in the same domain:

```csharp
ulong searchKeyHandle = GetSearchKeyHandleFromValidatedDeploymentConfiguration();
byte[] searchToken = cryptographicService.HmacWithKeyHandle(
    searchKeyHandle,
    domainSeparatedValue,
    hmacOptions);
```

`HmacWithKeyHandle` returns only the HMAC bytes. It does not generate a new key or include the handle in the result. Reusing a handle is appropriate only for an explicitly designed deterministic domain; ordinary HMAC creation should continue using `Hmac(keySourceId, ...)` so it receives fresh KeyManager material.

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

## Validation And Errors

Unsupported algorithm enum values and unsupported HMAC key sizes throw `NotSupportedException`.

Destination buffers that are too small throw `ArgumentException` with the destination parameter name. Malformed AES-GCM cipher artifacts shorter than `nonce[12] + tag[16]` also throw `ArgumentException`.

Validation methods return `false` for mismatched values, wrong-length hashes/HMACs, and HMAC handles that KeyManager cannot replay. Invalid validation options still throw.

AES-GCM decryption throws `CryptographicException` when authentication fails, including tampered nonce, tag, ciphertext, associated data, or key handle. `TryDecryptPostQuantum` instead returns `CryptographicResult<byte[]>` with a `CryptographicFailure` for expected failures.

Artifact parsers throw `ArgumentNullException` for null text input, `ArgumentException` for empty or whitespace keyed text input, and `FormatException` for malformed handle, Base64, Hex, or keyed artifact formats.

## Algorithm Status

`SymmetricEncryptionAlgorithms.AES128`, `AES192`, and `AES256` are implemented through AES-GCM.

`HashingAlgorithms.SHA256`, `SHA384`, `SHA512`, all declared SHA-3 variants, `SHAKE128`, and `SHAKE256` are implemented for unkeyed hashing. Legacy and BLAKE3 enum values remain unimplemented.

`HmacAlgorithms.HMACSHA256`, `HMACSHA384`, and `HMACSHA512` are implemented for keyed message authentication.

ML-KEM and ML-DSA have explicit implemented enums and APIs. The older `AsymmetricAlgorithms` enum still represents planned classical and later PQC surfaces and is not used by the implemented PQC methods.

The focused library requirements are recorded in [EncryptionManager requirements](docs/encryption-manager-requirements.md). All downstream-visible changes are tracked in [Public API changes](docs/public-api-changes.md).

## Build And Test

```bash
dotnet build Mrbr.Service.EncryptionManager.slnx
dotnet test Mrbr.Service.EncryptionManager.slnx
```

## Requirements

- .NET 11.0 or higher
- `Mrbr.Service.KeyManager` 2.0.0 or higher
