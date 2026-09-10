# Mrbr.Service.EncryptionManager

`Mrbr.Service.EncryptionManager` provides usage-agnostic cryptographic services for .NET. It performs cryptographic actions only and leaves caller-specific workflows outside this package.

**Version: 3.0.0-preview.1.** Requires KeyManager 3. See [release notes](RELEASE_NOTES.md) and [downstream adoption](docs/downstream-3.0.md).

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

builder.ConfigureKeyService(new KeyValidationOptions {
    ApplicationId = "MyApplication",
    // Enable only for deliberate first enrollment; disable after enrollment.
    AllowInitialEnrollment = true
});
builder.Services.AddEncryptionManager();
```

For a generic host or non-hosted application, supply `KeyValidationOptions` and
`IOptions<KeyServiceConfig>` when constructing KeyManager's singleton `KeyServiceOptions`,
then register `IKeyService` and call `AddEncryptionManager()`. The console example supplies
a deferred file loader so binding errors occur inside KeyManager's audit boundary.

Use a stable application identity and persistent history directory. Accept runtime candidates
explicitly with `KeyServiceOptions.Reload(loader)` or `ApplyConfiguration(config)`; setting
`reloadOnChange: true` alone does not change the accepted registry. A rejected update leaves
the active registry unchanged. Configuration validation/history persistence and source states
belong to KeyManager; source selection, enrollment approval and audit consumption belong to the host.

`AddEncryptionManager()` registers EncryptionManager services only. It expects KeyManager's singleton `IKeyService` registration. If `IKeyService` is missing, resolving or running an operation that needs key material fails clearly through DI or constructor validation.

## Key-source lifecycle

| Operation | Key access | Enabled | Disabled / Retired |
|---|---|---|---|
| Encrypt / EncryptText / EncryptPostQuantum | Generate | Allowed | Rejected by KeyManager |
| SignPostQuantum | Generate | Allowed | Rejected by KeyManager |
| Hmac(sourceId, ...) | Generate | Allowed | Rejected by KeyManager |
| Decrypt / DecryptText / DecryptPostQuantum | Replay | Allowed | Allowed |
| VerifyPostQuantum / ValidateHmac | Replay | Allowed | Allowed |
| HmacWithKeyHandle | Replay | Allowed | Allowed |
| Hash / ValidateHash | None | Unaffected | Unaffected |

The restriction is on **generating new keys**, not computing another HMAC using an existing
key. EncryptionManager delegates this enforcement to KeyManager rather than duplicating its
state checks. Existing signatures/HMACs must still validate and ciphertext must still decrypt
while the source is disabled or retired. Re-enabling a disabled source restores generation;
retirement is irreversible. Normal validation still rejects tampered artefacts.

Rotation is explicit: load an enabled replacement source and pass its ID for new encryption,
signing or fresh-key HMAC. EncryptionManager never silently selects a replacement. Existing
handles continue to identify the original source. Configuration GUIDs are not added to cipher,
signature or handle formats; index reuse remains a business-approved migration decision.

Attempting generation from a disabled/retired source propagates KeyManager's
`InvalidOperationException`. It is not a failed verification. Startup configuration rejection
uses `KeyConfigurationException`; host code can correlate its attempt ID with
`KeyConfigurationAudit.TryDequeue` records. External delivery, persistence, comparison and UI
remain downstream. The audit queue is process-local and non-durable; consume it on startup-failure
paths as well as during normal operation.

EncryptionManager owns standard encryption, hashing, HMAC, signing and serialization. Downstream
projects should call these operations directly and remove duplicate implementations or aliases
that add no behaviour. Helpers that build project-specific domain-separated inputs remain appropriate.

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

`HmacWithKeyHandle` supports enabled, disabled and retired sources, including when computing a
search token for a new lookup input. It replays the existing key; it does not create a key.
There is no additional source-state restriction in EncryptionManager or the data layer.

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
- `Mrbr.Service.KeyManager` 3.0.0-preview.1 (including its serialization/exception dependencies)

## Console smoke test

The checked-in configuration is **public, disposable demo material**, never a production secret.
It uses source 7 and a persistent GUID. The demo no longer reads the removed KeyServiceOptions.Value.
To create a separate fresh demo file (existing files are never overwritten):

```powershell
dotnet run --project Mrbr.Service.EncryptionManager.ConsoleTest -- --create-demo-config C:/temp/demo-keys.json
dotnet run --project Mrbr.Service.EncryptionManager.ConsoleTest -- --config C:/temp/demo-keys.json --history C:/temp/demo-key-history --enroll
# Subsequent launch: use the same configuration/history, without enrollment permission.
dotnet run --project Mrbr.Service.EncryptionManager.ConsoleTest -- --config C:/temp/demo-keys.json --history C:/temp/demo-key-history
```

The parent directory must exist. `--source ID` selects a source (default 7). Without `--history`,
KeyManager uses the application's LocalApplicationData directory. A first launch without
`--enroll` fails closed. The demo prints a round-trip result and non-secret audit artefacts;
configuration rejection returns exit code 1 and drains audit records. It does not implement a
watcher, delivery service or migration UI.

## Local package validation

Before KeyManager 3 is published, restore against its built package feed and compatible dependency
packages. For example, with the sibling repositories present:

```powershell
dotnet pack ../Mrbr.System.Exceptions -c Release -o artifacts/dependencies
dotnet pack ../Mrbr.System.Text.Json.Serialisation -c Release -o artifacts/dependencies
dotnet pack ../Mrbr.Service.KeyManager/Mrbr.Service.KeyManager -c Release -o artifacts/dependencies
dotnet restore Mrbr.Service.EncryptionManager.slnx --source artifacts/dependencies --source "https://api.nuget.org/v3/index.json"
dotnet build Mrbr.Service.EncryptionManager.slnx -c Release --no-restore
dotnet test Mrbr.Service.EncryptionManager.Tests -c Release --no-restore
```

Include any private feed needed for other Mrbr dependencies. Builds must use versioned packages;
do not overwrite cached 2.0.0 contents with a newer DLL. Tests isolate KeyManager's process-wide
registry using test-only reflection and temporary history directories; production must never use
that reset mechanism. No production reset API or duplicate cryptographic implementation is added.
