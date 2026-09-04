# EncryptionManager public API changes

This document records changes that downstream packages must account for after the EncryptionManager work is released. EF, Identity, database migration, and deployment policy are deliberately outside this document.

## Unreleased

### Package dependency

- `BouncyCastle.Cryptography` 2.6.2 is now a dependency of the single EncryptionManager package.
- Applications do not configure a provider. Native .NET PQC/SHA-3/SHAKE is selected when supported; Bouncy Castle is the automatic fallback.
- A cryptographic failure never causes provider fallback. Fallback is only for unavailable native capability.

### Added algorithms

- `MlKemAlgorithms`: `MLKEM512`, `MLKEM768`, and `MLKEM1024`.
- `MlDsaAlgorithms`: `MLDSA44`, `MLDSA65`, and `MLDSA87`.
- Hashing support added for `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, and `SHAKE256`.

### Added types

- `PostQuantumEncryptionOptions(MlKemAlgorithms algorithm)` requires an explicit ML-KEM parameter set and supports optional associated data.
- `PostQuantumSignatureOptions(MlDsaAlgorithms algorithm)` requires an explicit ML-DSA parameter set.
- `SignatureResult(ulong KeyHandle, byte[] Signature)` returns the replay handle and signature.
- `PostQuantumAlgorithmInfo` publishes private-seed, encapsulation, signature, and protected-data sizes.

### Added `ICryptographicService` members

```csharp
EncryptionResult EncryptPostQuantum(
    byte keySourceId,
    ReadOnlySpan<byte> dataToEncrypt,
    PostQuantumEncryptionOptions options);

byte[] DecryptPostQuantum(
    ulong keyHandle,
    ReadOnlySpan<byte> protectedData,
    PostQuantumEncryptionOptions options);

CryptographicResult<byte[]> TryDecryptPostQuantum(
    ulong keyHandle,
    ReadOnlySpan<byte> protectedData,
    PostQuantumEncryptionOptions options);

SignatureResult SignPostQuantum(
    byte keySourceId,
    ReadOnlySpan<byte> dataToSign,
    PostQuantumSignatureOptions options);

bool VerifyPostQuantum(
    ulong keyHandle,
    ReadOnlySpan<byte> signedData,
    ReadOnlySpan<byte> signature,
    PostQuantumSignatureOptions options);
```

The algorithm options are mandatory. No provider name is accepted or returned.

### Changed hashing API

- `HashOptions.OutputLengthInBytes` was added.
- It must be a positive value for `SHAKE128` and `SHAKE256`.
- `CryptographicService.GetHashLength(HashOptions)` was added for fixed-length and extendable-output algorithms.
- Existing `GetHashLength(HashingAlgorithms)` remains valid for fixed-length hashes and rejects SHAKE because SHAKE has no intrinsic output length.

### Added result-based failure types

- `CryptographicFailure` identifies expected invalid-data, authentication, unavailable-key, and cryptographic-operation failures.
- `CryptographicResult<T>` returns either a value or a known failure.
- `TryDecryptPostQuantum` uses this result contract. The throwing `DecryptPostQuantum` method remains available for callers that prefer exception semantics.

### Persisted representation

- ML-KEM protected data remains an opaque byte array paired with the existing KeyManager handle.
- Its internal version-one layout is ML-KEM ciphertext, twelve-byte AES-GCM nonce, sixteen-byte authentication tag, then encrypted datum.
- Provider identity is not persisted. The same seed and standard algorithm parameter set must be interoperable across native .NET and Bouncy Castle implementations.

### Downstream action (deferred)

- Do not update EF or Identity projects during this phase.
- When downstream propagation begins, pass explicit ML-KEM or ML-DSA options from external configuration and use `PostQuantumAlgorithmInfo` when selecting storage capacity.
- Continue treating the protected bytes as opaque; downstream code must not parse the internal layout.
