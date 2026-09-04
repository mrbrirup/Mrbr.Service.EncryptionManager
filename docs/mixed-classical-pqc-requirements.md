# Mixed Classical and Post-Quantum Data Protection Requirements

Status: proposed requirements and decision request  
Document version: 0.1  
Date: 2026-09-03  
Applies to: `Mrbr.Service.KeyManager`, `Mrbr.Service.EncryptionManager`, `Mrbr.Encryption.Data`, and `Mrbr.Encryption.Data.Identity`

## 1. Purpose

This document defines the requirements for supporting classical and post-quantum cryptographic protection in the same application. It also records the questions that must be answered before the post-quantum implementation and its public API are designed.

The current implementation is the classical baseline. It provides source-generated Entity Framework encryption and keyed deterministic hashes, externally configured source-key mappings, protected ASP.NET Core Identity lookups and tokens, and SQLite/PostgreSQL migration tooling. Post-quantum encryption, post-quantum storage, and classical-to-post-quantum re-encryption have not yet been implemented.

## 2. Terminology

- **Logical source key**: the name placed in an entity attribute, such as `PII`, `HIPAA`, or `IdentityCredential`.
- **SourceKeyId**: the externally configured identifier that maps a logical source key to KeyManager configuration.
- **Key handle**: the non-secret identifier stored with protected data and used to locate the required key and cryptographic metadata externally.
- **Datum**: one independently protected property value belonging to one entity instance.
- **DEK**: a randomly generated data-encryption key used to encrypt one datum.
- **AEAD**: authenticated encryption with associated data.
- **KEM**: a key-encapsulation mechanism used to establish or protect key material; it does not directly replace bulk-data encryption.
- **Classical profile**: a protection profile using the currently supported classical encryption path.
- **PQC profile**: a post-quantum or hybrid profile in which a PQC mechanism protects the per-datum key and an AEAD protects the datum.
- **Hybrid profile**: a profile combining independently derived classical and post-quantum secrets so that confidentiality does not depend on only one family of algorithms.
- **Routing hash**: a keyed deterministic digest used to obtain database candidates for a protected lookup.

## 3. Security objectives

The implementation shall:

1. Permit classical and PQC profiles to operate in the same process, `DbContext`, entity type, and database.
2. Permit different properties of one entity to use different logical source keys and protection profiles.
3. Permit old and new envelope versions to coexist during an explicitly controlled migration.
4. Preserve independent per-datum protection so that compromise of one data key does not directly disclose other data.
5. Keep key material, source-key configuration, algorithms, and cryptographic policy outside the database wherever decryption can remain reliable without storing them there.
6. Expose only the key handle and protected payload in ordinary encrypted storage, subject to a final decision on envelope version and storage metadata.
7. Authenticate protected data and its security-relevant context, not merely conceal its plaintext.
8. Continue treating every routing-hash match as a candidate that must be decrypted and compared with the requested plaintext.
9. Fail closed when configuration, keys, algorithms, payloads, associated data, hashes, or relational state are missing, ambiguous, unsupported, or invalid.
10. Avoid exceptions for expected data-plane failures where the calling API permits a result type.
11. Avoid automatic key creation, replacement, retirement, schema conversion, or bulk re-encryption during application startup.
12. Prevent secrets, plaintext, ciphertext, complete routing hashes, key material, and sensitive handles from entering logs or exception messages.

## 4. Scope

### 4.1 Included

- Configuration and validation of classical, PQC, and hybrid source-key profiles.
- KeyManager representation and resolution of the key material required by each profile.
- EncryptionManager dispatch without requiring entity code to select an algorithm.
- A versioned protected-payload contract.
- Source-generated EF model and persistence integration.
- Inline and/or indirect storage for larger protected payloads.
- Independent keyed hashes for searchable properties.
- SQLite and PostgreSQL support where the selected storage model is supported by the provider.
- ASP.NET Core Identity compatibility for entity types explicitly supported by the Identity package.
- Classical/PQC coexistence, migration, recovery, and performance testing.

### 4.2 Excluded from the first PQC increment

- Transparent conversion of every Identity entity without an explicit supported model and generated store.
- Automatic key rotation or re-encryption during normal application requests.
- Removal of primary and foreign keys needed for relational integrity.
- Encryption of data solely to make it searchable; search remains a separate keyed-hash concern.
- Claims that a profile is post-quantum secure until its complete construction, implementation, dependencies, configuration, and operational lifecycle have been reviewed.

## 5. Configuration requirements

### CFG-001: explicit logical source keys

Every `[Encrypted]` and `[Hashed]` declaration shall require an explicit non-empty logical source key. Parameterless forms shall not exist.

### CFG-002: external configuration

SourceKeyId values, cryptographic profiles, algorithms, key locations, active state, retirement state, and storage policies shall come from external deployment configuration or an external provider. They shall not be compiled into generated application code.

### CFG-003: no defaults

There shall be no implicit default SourceKeyId, encryption algorithm, hashing algorithm, key, or search-key handle. Missing required values shall prevent application startup.

### CFG-004: generated validation

The source generator shall generate the required `SourceKeyMapConfig` surface and validation for every referenced logical source key. Startup validation shall confirm that each configured profile is internally consistent and supported by the installed runtime components.

### CFG-005: independent encryption and search profiles

A property may be encrypted, hashed, or both. Its encryption profile and hash profile shall remain independently configurable, even when both attributes use the same logical source-key name.

### CFG-006: immutable cryptographic meaning

While an application is running, the cryptographic meaning of an existing key handle shall not change. Configuration reload shall not replace key material, algorithms, envelope interpretation, or storage interpretation for an existing handle.

### CFG-007: additive updates

Runtime configuration changes may add previously unknown, unique key handles. Existing handles may only undergo lifecycle changes explicitly permitted by the KeyManager state model. A retired key shall not become active again in the same running process.

### CFG-008: historical resolution

Decryption shall continue to resolve every retained key handle and its original profile for as long as any live datum, backup, replica, export, or recovery workflow can contain that handle.

## 6. Cryptographic requirements

### CRY-001: per-datum encryption

Each protected datum shall use independently generated per-datum key material. Key reuse across unrelated data shall not be introduced merely to improve PQC performance or reduce payload size.

### CRY-002: authenticated encryption

Bulk plaintext shall be protected with an approved AEAD construction. A PQC KEM shall establish or protect key material; it shall not be treated as a direct bulk-data cipher unless a separately reviewed algorithm explicitly provides that operation.

### CRY-003: hybrid construction

If hybrid protection is selected, the classical and post-quantum contributions shall be combined through a documented key-combining construction. Concatenating ad hoc secrets or independently encrypting without a defined security construction is prohibited.

### CRY-004: domain separation

Key derivation, routing hashes, and associated data shall use unambiguous, versioned domain separation that identifies the protection purpose without including secret values.

### CRY-005: associated data

The design shall decide which stable context is authenticated with each datum. Candidate fields include application/protocol domain, entity contract, property contract, tenant identifier, and immutable relational identifier. A value required for later decryption shall not be included unless its lifecycle and migration behavior are defined.

### CRY-006: algorithm agility

New algorithms and profile versions shall be additive. Existing protected data shall retain an unambiguous route to its original implementation until it is deliberately re-encrypted.

### CRY-007: implementation providers

Cryptographic providers shall be replaceable behind reviewed interfaces. Provider selection, native-library deployment, platform support, FIPS requirements, side-channel properties, memory clearing, and failure behavior shall be documented and tested.

### CRY-008: randomness

All DEKs, nonces, salts, KEM randomness, and identifiers that require randomness shall use an approved cryptographic random-number generator. Nonce uniqueness requirements shall be enforced by construction.

### CRY-009: signatures are separate

PQC encryption/key establishment and PQC signatures shall be treated as different capabilities. Adding a PQC KEM shall not imply that stored signatures or signed messages are post-quantum protected.

## 7. Envelope and storage requirements

### ENV-001: versioned contract

The protected representation shall have a versioned, length-delimited, bounds-checked contract. Parsing shall reject truncation, trailing ambiguity, impossible sizes, unsupported versions, and inconsistent fields without attempting partial recovery.

### ENV-002: handle-based resolution

The stored key handle shall resolve the external key material and immutable cryptographic profile required to interpret the payload. Whether a non-secret envelope-format version must also be stored is an explicit decision below.

### ENV-003: storage independence

EncryptionManager shall produce and consume a provider-independent protected payload. Entity Framework storage shall decide whether that payload is represented inline or by an indirect reference.

### ENV-004: storage modes

If both inline and indirect storage are supported, the storage mode shall be explicit in generated model configuration and shall not change at runtime for an existing mapped property.

### ENV-005: indirect payload integrity

An indirect payload row shall be transactionally consistent with its owning entity. Orphan prevention, cascade behavior, concurrency control, uniqueness, and deletion shall be enforced by schema constraints and generated persistence behavior.

### ENV-006: no cross-datum blob

Separately attributed entity properties shall remain independently protected. A convenience blob containing multiple logically independent sensitive fields shall not be introduced unless explicitly approved for that entity contract.

### ENV-007: provider mapping

SQLite and PostgreSQL mappings shall preserve the same logical contract while using appropriate provider types. PostgreSQL should use native binary/UUID types where appropriate; SQLite mappings shall preserve exact bytes and identifiers.

### ENV-008: bounds

Every decoder and persistence mapping shall enforce maximum permitted sizes before allocation. Maximum plaintext, ciphertext, encapsulation, associated-data, and complete-envelope sizes shall be defined per profile.

## 8. Entity Framework and source-generation requirements

### EF-001: no runtime reflection path

Entity discovery, protected-property metadata, configuration validation, persistence hooks, and supported query helpers shall be source generated wherever practicable. A reflection fallback shall not silently activate.

### EF-002: database-agnostic context

Core integration shall work with a database-agnostic `DbContext`, including derived `IdentityDbContext` types. Provider-specific schema behavior shall remain in provider-specific packages.

### EF-003: mixed profiles

Generated code shall support classical and PQC properties in one context and on one entity. It shall not assume one encryption algorithm or one payload size for the entire model.

### EF-004: persistence interception

Generated persistence behavior shall protect added and modified values before storage and materialize authenticated plaintext for application use. Save interception must define retry, transaction, change-tracking, and partial-failure semantics before it is used for indirect payload rows.

### EF-005: query safety

Direct predicates over encrypted plaintext properties shall produce analyzer diagnostics. Supported hash-search helpers shall compute routing hashes, retrieve all candidates, decrypt them, and perform the required comparison.

### EF-006: schema generation

Generated model configuration shall select safe column types, lengths, indexes, relationships, and delete behavior for the configured storage contract. It shall not derive a runtime-varying schema from reloadable configuration.

### EF-007: model determinism

All configuration that influences EF model shape shall be fixed before model construction and included in model-cache identity where necessary. Two tenants or deployments with different storage shapes shall not accidentally share an incompatible cached model.

### EF-008: atomic saves

Changes to an owner row, its protected payload rows, and related routing hashes shall commit atomically. A known protection failure shall prevent the complete save operation.

### EF-009: concurrency

Generated code shall define concurrency behavior for replacement, deletion, retry, and collision. It shall not overwrite a payload or routing row that has not been authenticated and matched to the expected datum.

## 9. Searchable hash requirements

### HASH-001: encryption independence

Searchable hashing shall remain separate from encryption. A PQC/hybrid-encrypted property may continue to use a keyed deterministic classical hash unless and until a different approved searchable construction is selected.

### HASH-002: externally provisioned keys

Routing hashes shall use externally provisioned stable search keys. Startup and deployment shall never silently generate or replace them.

### HASH-003: collision verification

Every returned candidate shall be decrypted, authenticated, normalized according to the declared contract, and compared with the requested plaintext. Hash equality alone shall never establish identity.

### HASH-004: low-entropy inputs

Low-entropy fields shall support approved composite routing inputs to reduce candidate counts and limit simple frequency exposure. Composite encodings shall be versioned, length-delimited, domain-separated, and unambiguous.

### HASH-005: key separation

Encryption keys, KEM keys, derivation keys, and searchable-hash keys shall be purpose-separated even when they belong to the same logical data group.

### HASH-006: search-key migration

Changing or retiring a search key shall require explicit recalculation of every dependent routing hash and verification of every affected candidate before the old search key is retired.

## 10. Identity requirements

### ID-001: framework compatibility

Generated stores shall preserve the observable contracts of the supported ASP.NET Core Identity version. Result-based internal failures may be translated to a typed exception only where an Identity interface cannot return a result.

### ID-002: explicit entity coverage

Users, roles, claims, external logins, tokens, recovery codes, authenticator keys, and passkeys shall be enabled only through separately reviewed entity/store phases. Referencing Identity shall not silently protect unsupported tables.

### ID-003: relational keys

Required primary and foreign keys shall remain relationally usable. Sensitive natural or composite keys shall be replaced with surrogate keys and verified keyed routing where necessary.

### ID-004: provider parity

Each supported Identity protection phase shall pass equivalent SQLite and PostgreSQL functional, raw-storage, collision, corruption, concurrency, migration, and recovery tests.

## 11. Failure handling requirements

### FAIL-001: expected failures

Expected data-plane failures shall use a dependency-free result/union type where the API permits it. Stable failure codes shall cover at least malformed payload, authentication failure, unavailable key, retired key, unsupported profile/version, hash mismatch, ambiguous candidate, size violation, and bounded persistence conflict.

### FAIL-002: exceptions

Programming errors, invalid startup configuration, cancellation, resource exhaustion, provider failures, and framework boundaries that require exceptions may remain exceptions. Exceptions shall not contain protected values.

### FAIL-003: no fallback decryption

Failure to resolve or authenticate the selected profile shall not trigger guesses across other algorithms, keys, tenants, properties, or envelope formats.

### FAIL-004: bounded work

Parsing, candidate verification, database retry, and provider retry shall have explicit bounds. Corrupt or malicious input shall not cause unbounded allocation, unbounded candidate scans, or indefinite retry.

## 12. Migration and lifecycle requirements

### MIG-001: conscious operation

Classical-to-PQC, PQC-to-new-PQC, key recovery, and search-key replacement shall be explicit operator-controlled processes with documented availability, backup, replica, export, and rollback consequences.

### MIG-002: per-datum rewrite

Changing the encryption profile or retiring an encryption/KEM key shall decrypt, authenticate, re-protect, and verify every affected datum. Metadata-only key rotation shall not be presented as sufficient.

### MIG-003: coexistence

Migration tooling shall permit old and new key handles/profile versions to coexist for a bounded observation period. New writes shall use only the currently active write profile; reads shall resolve all approved historical profiles.

### MIG-004: staged verification

Migration shall use bounded batches, durable non-secret checkpoints, idempotent retries, full verification, explicit cutover, and separately approved removal of old protected or plaintext data.

### MIG-005: backups and replicas

Key/profile retirement shall include backups, replicas, exports, caches, queues, and disaster-recovery copies in its plan. A key shall not become irrecoverable while retained data still depends on it.

### MIG-006: downgrade prevention

A datum protected under a newer required profile shall not be silently rewritten with a weaker or older profile. Any authorized downgrade shall be an explicit audited migration policy.

## 13. Performance and capacity requirements

### PERF-001: measurable components

Benchmarks shall separately measure AEAD, KEM encapsulation/decapsulation, key combination/derivation, encoding, database persistence, candidate verification, and complete request workflows.

### PERF-002: realistic distributions

Tests shall cover representative plaintext sizes, candidate counts, entity batch sizes, concurrent writers, connection latency, and both supported database providers.

### PERF-003: storage accounting

Capacity planning shall record payload expansion, index size, indirect-row overhead, WAL/log growth, backup growth, replication traffic, and migration working space.

### PERF-004: controlled caching

Caching of public configuration or immutable key metadata may be considered. Plaintext, DEKs, shared secrets, and decapsulated material shall not be cached without a separately approved lifetime and memory-threat model.

### PERF-005: no security bypass

Performance optimizations shall not skip authentication, candidate comparison, domain separation, configuration validation, or required atomic database behavior.

## 14. Verification and release requirements

Before mixed classical/PQC support is declared production-ready:

- Known-answer and negative cryptographic tests shall cover every supported profile and envelope version.
- Classical-only, PQC-only, and mixed-profile contexts shall pass.
- One entity containing both classical and PQC properties shall round-trip correctly.
- Historical classical rows and new PQC rows shall coexist and be readable according to lifecycle policy.
- Tampered handle, payload, encapsulation, nonce, tag, associated data, and indirect reference shall fail closed.
- Missing, inactive, retired, and wrong-domain keys shall produce the agreed failure result.
- Raw database inspection shall reveal no protected plaintext.
- Hash-collision and low-entropy candidate tests shall verify every returned candidate.
- SQLite and PostgreSQL schema, transaction, retry, concurrency, migration, and deletion behavior shall pass.
- Abrupt termination shall be injected at every durable migration boundary.
- Logs, metrics, traces, exceptions, and checkpoints shall be inspected for data leakage.
- Dependency provenance, supported platforms, native deployment, vulnerability response, and update policy shall be documented.
- Performance and storage baselines shall be recorded on representative release hardware.
- A cryptographic and architectural review shall be completed before public package claims are made.

## 15. Decisions already established

The following decisions are treated as established unless explicitly reopened:

| ID | Decision |
|---|---|
| D-001 | Entity attributes name an explicit logical source key; they do not contain SourceKeyId or algorithm choices. |
| D-002 | SourceKeyId, algorithms, keys, handles, and cryptographic policy are externally configured. |
| D-003 | Missing required configuration prevents application startup. |
| D-004 | There are no parameterless `[Encrypted]` or `[Hashed]` forms and no implicit cryptographic defaults. |
| D-005 | Encryption and searchable hashing may both be applied to one property. |
| D-006 | Hash matches are candidates and must be verified against decrypted plaintext. |
| D-007 | Low-entropy searches may use additional approved fields in a structured composite routing hash. |
| D-008 | Key handles, rather than descriptive key metadata, are stored with protected data. |
| D-009 | Existing key material and cryptographic meaning cannot be replaced during runtime configuration reload. |
| D-010 | Key recovery and whole-dataset re-encryption are conscious, separately operated processes. |
| D-011 | Expected protection failures use results where possible; exceptions remain for unexpected or framework-required boundaries. |
| D-012 | Relational primary and foreign keys remain available to EF; sensitive alternate routing data is protected separately. |

## 16. Questions and decisions required

The recommended answer is identified where there is currently enough context to make one. These recommendations are proposals, not approvals.

### Cryptographic construction

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-001 | What does the first “PQC profile” mean? | PQC KEM plus AEAD; hybrid classical KEM/PQC KEM plus AEAD; another reviewed construction. | Begin with a hybrid KEM construction plus per-datum AEAD, while retaining a separately selectable classical profile. |
| Q-002 | Which exact algorithms and parameter sets are approved? | Must include security level, provider/library, platform availability, payload size, and expected lifetime. | Decide only after a small provider spike and benchmark; do not encode names in attributes. |
| Q-003 | Is one fresh DEK generated for every property value on every write? | Preserve current per-datum objective; decide whether unchanged values are re-encrypted on unrelated entity updates. | Fresh DEK when the protected property is inserted or logically changed; do not rewrite unchanged data. |
| Q-004 | How are classical and PQC shared secrets combined in hybrid mode? | A reviewed KDF combiner with versioned domain separation is required. | Treat the combiner as a named, versioned cryptographic profile and obtain external review. |
| Q-005 | Which values become authenticated associated data? | Entity/property contract, tenant, owner ID, schema version; mutable values complicate updates. | Authenticate stable generated domain/property identifiers and tenant identity where tenant assignment is immutable. Decide owner-ID binding separately. |
| Q-006 | Are PQC signatures in scope? | Data encryption/key establishment does not protect signatures. | Keep signatures as a separate future workstream unless an existing stored signature has a defined threat requirement now. |

### Handle and envelope contract

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-007 | Is the existing textual `{handle}:{cipher}` representation retained, replaced, or wrapped? | Text is operationally simple; binary is smaller and easier to bound precisely; either needs versioning. | Define a canonical binary envelope first and allow a strict Base64/text transport only where a string column is required. |
| Q-008 | May the database expose a non-secret envelope-format version in addition to the key handle? | A version aids safe parsing; the handle could resolve everything externally but increases reliance on permanent external metadata. | Store only the minimum parse version plus the handle. Do not store algorithm, source-key name, or descriptive profile metadata. |
| Q-009 | Does a key handle permanently bind one immutable algorithm/profile version? | Required if no algorithm metadata is stored with each datum. | Yes. Never reinterpret an existing handle; issue a new handle for every incompatible profile change. |
| Q-010 | How long must historical handle metadata remain resolvable? | Live database only; plus backup/replica/export retention; legal archive period. | At least as long as any retained copy can contain the handle, with an explicit destruction/retirement record afterward. |
| Q-011 | What maximum plaintext and envelope sizes are supported initially? | Identity strings, ordinary PII, documents/images, provider limits, denial-of-service bounds. | Establish a bounded small/medium datum profile first; treat documents and media as a separate streaming/blob design. |

### Database storage

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-012 | When is a protected payload stored inline versus indirectly? | Always inline; always side table; generated per-property policy; size threshold at runtime. Runtime thresholds complicate schema and queries. | Generated per-property storage policy fixed at model build time; no runtime size-based switching in the first version. |
| Q-013 | What is the indirect storage shape? | One generic payload table; one table per entity; one table per entity/property; table splitting. | Prototype one generic strongly constrained payload table versus one entity-owned table, then select using measured query/storage behavior. |
| Q-014 | What remains in the owning column when storage is indirect? | UUIDv7 foreign key; shared owner primary key; no column and a generated navigation. | Prefer an application-generated UUIDv7 payload ID with a real foreign-key constraint unless table-splitting measurements show a clear benefit. |
| Q-015 | Is each protected property a separate payload row? | Maximum isolation and consistent mental model versus row/relationship overhead. | Yes for the first design, matching the established “encrypt each field separately” decision. |
| Q-016 | Which side owns the foreign key and cascade behavior? | Owner points to payload; payload points to owner; shared key. Consider insert/delete order and orphan risk. | Decide through an EF prototype; require atomic save and database-enforced orphan prevention in every case. |
| Q-017 | May classical values also use indirect storage? | PQC-only creates different storage semantics; profile-independent storage simplifies migration but adds overhead. | Make storage policy independent of algorithm so selected high-volume/large fields can retain one schema across classical/PQC migration. |
| Q-018 | Are payload rows permitted in a separate schema, tablespace, or database? | Same transaction is simplest; a separate database makes atomicity and availability substantially harder. | Support a separate schema/tablespace later if useful; keep owner and payload in the same transactional database initially. |

### Configuration and lifecycle

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-019 | Does one logical source key select exactly one active write profile at a time? | One profile simplifies writes; multiple profiles require a selection rule. | Exactly one active write profile per logical source key, with multiple historical read profiles resolved by handle. |
| Q-020 | Can profile selection vary by tenant? | Useful isolation; affects EF model caching only if storage shape varies. | Allow tenant-specific handles/keys later, but require one generated storage shape per mapped property. |
| Q-021 | What are the complete key states and transitions? | Proposed: active, inactive, retired; define read/write permissions for each and restart behavior. | Specify and test a formal state machine before PQC keys are introduced. |
| Q-022 | Can inactive keys decrypt existing data? | “Inactive” may mean no new writes, or temporarily unusable for all operations. | Define separate read-enabled and write-enabled capabilities rather than relying on one ambiguous flag. |
| Q-023 | Who supplies and validates PQC public/private material? | Configuration, HSM/KMS, file/secret store, remote service; availability and latency differ. | KeyManager owns resolution behind an interface; application configuration contains identifiers and policy, not private material. |
| Q-024 | What happens when the PQC provider is unavailable? | Fail startup, fail affected operations, permit classical fallback. Silent fallback is dangerous. | No cryptographic downgrade. Fail startup when the active write profile is unavailable; return a stable failure for historical reads that later lose availability. |

### Search and low-entropy data

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-025 | Does HMAC-SHA-256 remain the initial routing-hash construction for PQC-encrypted data? | Encryption and lookup have different threat models; changing the hash requires full recalculation. | Retain independently keyed HMAC-SHA-256 initially, document its threat model, and keep hash algorithm agility external. |
| Q-026 | Which composite-search definitions are required first? | Postcode plus country/tenant/address fields; Identity routes already have defined composites. | Define composites per business lookup, never automatically combine arbitrary entity fields. |
| Q-027 | Are unique indexes permitted on routing hashes for low-entropy fields? | A collision must fail closed; business data may legitimately duplicate. | Only when the logical value is genuinely unique. Otherwise use a non-unique index and verify every candidate. |
| Q-028 | What candidate-count limit triggers refusal or an alternate query requirement? | Prevents unbounded work but can make legitimate low-entropy searches unavailable. | Make a configurable bounded limit with metrics and a stable “candidate limit exceeded” failure; decide limits from benchmarks. |

### Entity Framework and Identity scope

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-029 | Which EF mechanism owns indirect payload persistence? | Save interceptor, generated store/repository methods, owned entity mapping, table splitting. | Build focused EF prototypes before selecting; Identity-specific stores may still need generated operations even if general EF uses interception. |
| Q-030 | Is table splitting still a candidate for PQC payloads? | Same table does not solve large-row pressure; a separate entity mapped to the same table is not physically separate storage. | Test it for mapping convenience only; use a physically separate table when the goal is moving large blobs out of the primary row. |
| Q-031 | Which Identity entity receives mixed/PQC support first? | Existing protected tokens, users, roles, claims, external logins, passkeys. | Extend the already protected token model first because it has migration tooling and independent encrypted fields. |
| Q-032 | How are passkey binary fields divided? | Per-field encryption was preferred, but exact schema and query semantics remain unknown. | Audit the concrete target Identity schema/version before defining attributes or storage. |
| Q-033 | Must the first PQC release support both SQLite and PostgreSQL? | Provider parity improves confidence; SQLite may not represent production storage behavior. | Yes for correctness; performance claims should be based primarily on PostgreSQL and representative deployment infrastructure. |

### Migration, operations, and release

| ID | Decision required | Options or considerations | Current recommendation |
|---|---|---|---|
| Q-034 | What is the first supported migration direction? | Classical to hybrid; classical to PQC-only; hybrid profile upgrade. | Classical to hybrid, retaining classical reads during a bounded observation period. |
| Q-035 | Are new writes switched before, during, or after backfill? | Offline migration is simpler; online dual-write requires a reviewed bridge. | Begin with an offline/read-only migration consistent with the existing Identity token migrator. |
| Q-036 | What proves a re-protected datum is correct? | Successful authentication only; decrypt-and-compare; application-level invariant checks. | Decrypt the new representation and compare with the authenticated old plaintext before checkpoint progress is committed. |
| Q-037 | When may old classical payloads and keys be removed? | After observation, backups/replicas/exports, recovery evidence, and explicit approval. | Use the existing separately approved plaintext-removal model, expanded to old protected payload and key retirement. |
| Q-038 | Is an external cryptographic review required before public release? | Scope may include construction, provider, envelope, source generation, migration, and operational guidance. | Yes. Plan it before freezing the first PQC public API and storage contract. |
| Q-039 | Which platforms must the selected PQC provider support? | Windows/Linux, x64/Arm64, containers, cloud services, trimming/AOT, FIPS environments. | List supported deployment targets before choosing a provider, because this can eliminate otherwise suitable implementations. |
| Q-040 | What performance and capacity thresholds are release gates? | Latency, throughput, allocation, payload size, database growth, migration duration. | Define thresholds from a representative application workload before implementation is labelled production-ready. |

## 17. Suggested response-document format

Create a companion file such as `mixed-classical-pqc-decisions.md`. Answers can use this compact structure:

```markdown
# Mixed Classical and PQC Decisions

Requirements document: mixed-classical-pqc-requirements.md version 0.1

## Q-001 — First PQC profile

Decision: Hybrid classical/PQC KEM plus per-datum AEAD.

Reasoning: ...

Constraints or follow-up work: ...

## Q-002 — Algorithms and parameter sets

Decision: Deferred until provider spike.

Candidates to test: ...

Acceptance evidence required: ...
```

An answer may be `Approved`, `Rejected`, `Modified`, or `Deferred`. A deferred answer should state what evidence or prototype is required to decide it. Once answered, decisions should be copied into an architecture decision record before implementation freezes the relevant public contract.

## 18. Proposed implementation gates

1. Approve the threat model, terminology, and decisions Q-001 through Q-011.
2. Build an isolated cryptographic-provider spike with no EF dependency.
3. Benchmark candidate profiles and establish exact envelope bounds.
4. Decide storage questions Q-012 through Q-018 using SQLite/PostgreSQL EF prototypes.
5. Implement KeyManager immutable handle/profile resolution and lifecycle validation.
6. Implement EncryptionManager classical/PQC/hybrid dispatch and result failures.
7. Extend source generation for fixed storage policies and mixed-profile models.
8. Add provider schema, transaction, concurrency, and malicious-payload tests.
9. Extend one protected Identity area and its explicit offline migrator.
10. Complete external cryptographic review, operational documentation, and release benchmarks.
