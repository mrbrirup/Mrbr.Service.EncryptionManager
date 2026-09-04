# EncryptionManager requirements

## Scope

EncryptionManager provides independent cryptographic operations for classical and post-quantum algorithm families:

- encryption and data protection;
- hashing and keyed authentication;
- digital signatures.

EF, Microsoft Identity, database schemas, migration operations, release policy, and business continuity decisions are downstream concerns and are not requirements of this library.

## Configuration and selection

- Algorithms and KeyManager source identifiers are chosen externally by the consuming application.
- Security-sensitive algorithms have no implicit PQC default.
- Native .NET implementations are used when the runtime reports that the capability is supported.
- Bouncy Castle is bundled in the same package and is selected automatically when native support is unavailable.
- Provider choice is not application configuration and is not part of the public operation contract.
- Authentication, malformed data, invalid keys, and other operation failures must not trigger a retry with another provider.

## Key material

- KeyManager remains algorithm-agnostic and generates or replays the requested number of bytes.
- EncryptionManager owns algorithm-specific size knowledge.
- The persisted handle is sufficient to replay the private seed; private key material is not persisted alongside application data.
- Temporary seed, shared-secret, and derived-key buffers are cleared after use.

## ML-KEM data protection

- Support ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- Reconstruct the ML-KEM private key from the KeyManager seed.
- Use the encapsulated shared secret to derive an AES-256 key with HKDF-SHA-256 and a versioned domain label.
- Encrypt the datum with AES-256-GCM.
- Authenticate the KeyManager handle and caller-provided associated data.
- Return only the handle and opaque protected bytes.

## ML-DSA signatures

- Support ML-DSA-44, ML-DSA-65, and ML-DSA-87.
- Reconstruct signing material from the KeyManager seed.
- Return the handle and signature bytes.
- Verification returns `false` for expected signature mismatch and invalid signature length.

## Hashing

- Classical SHA-2 hashing remains independent from encryption.
- Support SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512.
- Support SHAKE128 and SHAKE256 with an explicit positive output length.
- Hash choice is independent of whether persisted data uses classical or PQC protection.

## Compatibility and tests

- Every parameter set must round-trip through its automatically selected provider.
- Tampering must fail authentication or verification.
- Seed replay must reconstruct the same logical key.
- Native and Bouncy Castle implementations must interoperate from the same seed when native support is available on the test host.
- A host without native support must run the Bouncy Castle path without configuration.
- Public API changes must be recorded in `docs/public-api-changes.md` before downstream packages are updated.

## Deferred work

- Result types for expected decryption and validation failures will be introduced in a separate, documented API pass so that failure semantics are consistent across classical and PQC operations.
- Classical public options still contain historical defaults. Removing those defaults is a separate breaking API change and must be propagated deliberately.
- Classical public-key encryption and classical digital-signature APIs remain to be completed.
- SLH-DSA and other declared PQC algorithms are later milestones; the first production PQC milestone is ML-KEM plus ML-DSA.
