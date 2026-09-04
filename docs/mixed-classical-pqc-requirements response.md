# Mixed Classical and Post-Quantum Data Protection Requirements

## Responses

### 5. Configuration requirements

> **CFG-001: explicit logical source keys**  
> Every [Encrypted] and [Hashed] declaration shall require an explicit non-empty logical source key. Parameterless forms shall not exist

 - Correct. 
 - Every [Encrypted] and [Hashed] declaration shall require an explicit non-empty logical source key

> **CFG-002: external configuration**  
> SourceKeyId values, cryptographic profiles, algorithms, key locations, active state, retirement state, and storage policies shall come from external deployment configuration or an external provider. They shall not be compiled into generated application code.

- Correct
- There are no magic strings or numbers
- All configuration comes from an external source

> **CFG-003: no defaults**  
> There shall be no implicit default SourceKeyId, encryption algorithm, hashing algorithm, key, or search-key handle. Missing required values shall prevent application startup.  

- Correct
- There are no default values for any value required for a Key, Encryption, Hashing, etc
- Missing values prevents application starting
- Security cannot work without them and these projects' priority is security 

> **CFG-004: generated validation** 
> The source generator shall generate the required SourceKeyMapConfig surface and validation for every referenced logical source key. Startup validation shall confirm that each configured profile is internally consistent and supported by the installed runtime components.

- Correct
- Configuration is built from what the developer has coded in the attributes
- Failing to provide a config value is a missing value and fails, see CFG-003

> **CFG-005: independent encryption and search profiles**  
> A property may be encrypted, hashed, or both. Its encryption profile and hash profile shall remain independently configurable, even when both attributes use the same logical source-key name.

- Correct
- It is down to the developer/analyst to determine which is the most appropriate method of data security
- The application does not apply rules to determine the rationale for their decision

> **CFG-006: immutable cryptographic meaning** 
> While an application is running, the cryptographic meaning of an existing key handle shall not change. Configuration reload shall not replace key material, algorithms, envelope interpretation, or storage interpretation for an existing handle.

- Correct
- Changing any values in the key generation/derivation could render data unreadable

> **CFG-007: additive updates** 
> Runtime configuration changes may add previously unknown, unique key handles. Existing handles may only undergo lifecycle changes explicitly permitted by the KeyManager state model. A retired key shall not become active again in the same running process.

- Correct
- The keys cannot change, as per CFG-007
- Addttive keys allows for times when the adminstrators may wish to rotate or migrate keys

> **CFG-008: historical resolution** 
> Decryption shall continue to resolve every retained key handle and its original profile for as long as any live datum, backup, replica, export, or recovery workflow can contain that handle.

- Correct
- The key handle is required for any encryption/decryption process

---



### 6. Cryptographic requirements

> **CRY-001: per-datum encryption**  
> Each protected datum shall use independently generated per-datum key material. Key reuse across unrelated data shall not be introduced merely to improve PQC performance or reduce payload size.

- Correct
- There is no caching of keys. 
- It is possible, but highly unlikely, the same key could be generated twice, but there is no history for their creation so one will never know that an identical key was created
- Retaining Keys is a security risk from read keys from memory

> **CRY-002: authenticated encryption**  
> Bulk plaintext shall be protected with an approved AEAD construction. A PQC KEM shall establish or protect key material; it shall not be treated as a direct bulk-data cipher unless a separately reviewed algorithm explicitly provides that operation.

- Unclear. Need to discuss

> **CRY-003: hybrid construction**  
> If hybrid protection is selected, the classical and post-quantum contributions shall be combined through a documented key-combining construction. Concatenating ad hoc secrets or independently encrypting without a defined security construction is prohibited.

- Unclear. What is the key-combining construction?

> **CRY-004: domain separation**  
> Key derivation, routing hashes, and associated data shall use unambiguous, versioned domain separation that identifies the protection purpose without including secret values.

- Correct
- The developer will define the domain that the data belongs to. The protection is determined from config and used by the EncryptionManager

> **CRY-005: associated data**  
> The design shall decide which stable context is authenticated with each datum. Candidate fields include application/protocol domain, entity contract, property contract, tenant identifier, and immutable relational identifier. A value required for later decryption shall not be included unless its lifecycle and migration behavior are defined.

- Unclear, confirm the following is what you are asking about
- Data must be use the Attributes to determine how they are going to be encrypted
- If there is associated data and that is concatenated with a delimiter then the decorated property must provide appropriate { get; set; } to build the value. It is not the respnsibility of the EncryptionManager to provide utilities for this

> **CRY-006: algorithm agility**  
> New algorithms and profile versions shall be additive. Existing protected data shall retain an unambiguous route to its original implementation until it is deliberately re-encrypted.

- Correct
- No values values required for Key or Encryption Managers can be replaced.
- Replacing one algorithm with another risks blocking data being read. 
- If there are multiple applications, web/micro services running. Stoping one fo these or adding a new one would create an inconsistent state, that would be difficult to recover from

> **CRY-007: implementation providers**  
> Cryptographic providers shall be replaceable behind reviewed interfaces. Provider selection, native-library deployment, platform support, FIPS requirements, side-channel properties, memory clearing, and failure behavior shall be documented and tested.

- Correct
- For example PQC can be handled natively by .Net 11+, running Windows 11+, and Linux. Running on a system that is not configured for this would have afall back of Bouncy Castle. The same result, but slower as it is application bound instead of OS bound


> **CRY-008: randomness**  
> All DEKs, nonces, salts, KEM randomness, and identifiers that require randomness shall use an approved cryptographic random-number generator. Nonce uniqueness requirements shall be enforced by construction.

= Correct
- All randomness is from Cryptographically sound source
- Even if a value is required from a finite collection, such as Base94, the selection of the value from that collection will be Crytographically based

> **CRY-009: signatures are separate**  
> PQC encryption/key establishment and PQC signatures shall be treated as different capabilities. Adding a PQC KEM shall not imply that stored signatures or signed messages are post-quantum protected.

- Correct
- All encryption is explcit based on its configuration. 
- If data is configured to have AES-256 then it mus be processed as such.
    - It may be possible that the data could be considerd HMAB does not mean that it is. Correctly guessing the algorithm of a datum does not make it so


### 7. Envelope and storage requirements
> **ENV-001: versioned contract** 
> The protected representation shall have a versioned, length-delimited, bounds-checked contract. Parsing shall reject truncation, trailing ambiguity, impossible sizes, unsupported versions, and inconsistent fields without attempting partial recovery.

- Correct
- Unbounded data can have undesirable/unexpected effects, overflows, extended processing times

> **ENV-002: handle-based resolution** 
> The stored key handle shall resolve the external key material and immutable cryptographic profile required to interpret the payload. Whether a non-secret envelope-format version must also be stored is an explicit decision below.

- Correct
- All secured data will have a key for its payload
- An issue with encrypting dataum is that is cannot easily be processed
- Theere may be times that data is decrypted to create an ephemeral data set that can deleted after its use, such as an email shot.

> **ENV-003: storage independence** 
> EncryptionManager shall produce and consume a provider-independent protected payload. Entity Framework storage shall decide whether that payload is represented inline or by an indirect reference.

- Correct
- EncryptionManager is designed only for one thing, encryption. The developer decides what the data is for and its persistence method

> **ENV-004: storage modes** 
> If both inline and indirect storage are supported, the storage mode shall be explicit in generated model configuration and shall not change at runtime for an existing mapped property.

- Correct
- The application creates generates the storage mode from the Attributes the developer assigns.
- There may be a valid reason to have both storage methods.
    - Encrypted data may be stored with its long-term associated data for its domain. But a temporary store may be used, such as for out-boxes or side cars, such as confirmation emails. The temporary dat is deleted on confirmation keeping the active temporary data table in a minimal state.

> **ENV-005: indirect payload integrity** 
> An indirect payload row shall be transactionally consistent with its owning entity. Orphan prevention, cascade behavior, concurrency control, uniqueness, and deletion shall be enforced by schema constraints and generated persistence behavior.

- All associated data must be atomic, 
    - A single row in a table
    - Created by an interceptor
    - HasTable from entity frame work
- Data that must not be part of that transaction must handled seprately
    - Logging information could be firer and forget. Ideally not, but the application should not fail because of a logging issue
    - Audit trails would be consider associated data and must be part of the transaction

> **ENV-006: no cross-datum blob** 
> Separately attributed entity properties shall remain independently protected. A convenience blob containing multiple logically independent sensitive fields shall not be introduced unless explicitly approved for that entity contract.

- Correct
- Every property has its own configuration based on the Attributes assigned
- Data that is grouped for convenience to create a datum can only be handled in a property 
    - If the data is not going to be saved individually it must be explcitly assigned [NotMapped]
    - The datum created from data is returned from the { get; } and parsed
    - The { set; } method turns the data into the datum, concatenation and delimiters 

> **ENV-007: provider mapping** 
> SQLite and PostgreSQL mappings shall preserve the same logical contract while using appropriate provider types. PostgreSQL should use native binary/UUID types where appropriate; SQLite mappings shall preserve exact bytes and identifiers.

- Correct
- The database provider bound must be handled in their respective implementations.
    - Any differences in how the data is persisted must be handled by the relevant DbContext
    - The values passed from the DbContext must be the same, whatever the source or processing required to get there


> **ENV-008: bounds** 
> Every decoder and persistence mapping shall enforce maximum permitted sizes before allocation. Maximum plaintext, ciphertext, encapsulation, associated-data, and complete-envelope sizes shall be defined per profile.

- Unclear
- Maximum sizes for properties would seem to come from the DataAnnotations, such as MaxLengthAttribute. 
- Any sizes before decoding would need t be handled with the most appropriate mehtods, Stream, Memory<>, Span<>, etc.
- Please confirm this

### 8. Entity Framework and source-generation requirements
> **EF-001: no runtime reflection path** 
> Entity discovery, protected-property metadata, configuration validation, persistence hooks, and supported query helpers shall be source generated wherever practicable. A reflection fallback shall not silently activate.

- Correct
- These libraries are design to be optimised, and highly performant
- Reflection is a slower process to achive the same thing

> **EF-002: database-agnostic context** 
> Core integration shall work with a database-agnostic DbContext, including derived IdentityDbContext types. Provider-specific schema behavior shall remain in provider-specific packages.

- Correct
- We have the two examples, SSQLite and Postgress, but this is designed to be used by any database implementation

> **EF-003: mixed profiles** 
> Generated code shall support classical and PQC properties in one context and on one entity. It shall not assume one encryption algorithm or one payload size for the entire model.

- Correct
- The models defined for EF are independant from the Key and Encryption Manager.
- The Entities are ignorant of how they are persisted or encrypted

> **EF-004: persistence interception** 
> Generated persistence behavior shall protect added and modified values before storage and materialize authenticated plaintext for application use. Save interception must define retry, transaction, change-tracking, and partial-failure semantics before it is used for indirect payload rows.

- Correct
- Interceptors are designed to alter and augment data for persistence, and then attach that data as part of any transaction, and be handled as such

> **EF-005: query safety** 
> Direct predicates over encrypted plaintext properties shall produce analyzer diagnostics. Supported hash-search helpers shall compute routing hashes, retrieve all candidates, decrypt them, and perform the required comparison.

- Correct
- The chance of a collsions is incredibly small, but none-the-less these libraries are about data security. All opportunities to make it secure must be taken. Therefore hash0search can never mae the assumption that there will only ever be one hash value, even in high-entropy data sets


> **EF-006: schema generation** 
> Generated model configuration shall select safe column types, lengths, indexes, relationships, and delete behavior for the configured storage contract. It shall not derive a runtime-varying schema from reloadable configuration.

- Correct
- Models and schemas are derived from the Entities used for the DbContext
- Changes in schema will only be produced when the Entites change.
- Migrations can be created from these changes. 
- External configuration has no influence on the schema

> **EF-007: model determinism** 
> All configuration that influences EF model shape shall be fixed before model construction and included in model-cache identity where necessary. Two tenants or deployments with different storage shapes shall not accidentally share an incompatible cached model.

- Correct
- The developer is responsible for the models and schemas. 
- Migrations with their respective application version are tested before deployment to production

> **EF-008: atomic saves** 
> Changes to an owner row, its protected payload rows, and related routing hashes shall commit atomically. A known protection failure shall prevent the complete save operation.

- Correct
- All data related to a row, hashes, encrypted data must be saved atomically in a transaction

> **EF-009: concurrency** 
> Generated code shall define concurrency behavior for replacement, deletion, retry, and collision. It shall not overwrite a payload or routing row that has not been authenticated and matched to the expected datum.

- Correct
- The concurrency method have been defined by us for these libraries. 
- Source generators for these libraries a created to create optimised, typed functions that implement these rules
- No source genorators will be created to break these rules and will be tested before deployment. 


### 10. Identity requirements
> **ID-001: framework compatibility** 
> Generated stores shall preserve the observable contracts of the supported ASP.NET Core Identity version. Result-based internal failures may be translated to a typed exception only where an Identity interface cannot return a result.

- Correct
- Exceptions are thrown when we an outcome is unanticipated
- Just because something is an error does not mean it's not a predictable outcome
    - Network failure is not a desired result, but we know it can happen, so why throw an Exception
        - The Exception can still be logged and details fed back to the calling function with out Exception handlin overhead

> **ID-002: explicit entity coverage** 
> Users, roles, claims, external logins, tokens, recovery codes, authenticator keys, and passkeys shall be enabled only through separately reviewed entity/store phases. Referencing Identity shall not silently protect unsupported tables.

- Correct
- As all data must be atomic, the persistence functions of Identity will follow this rule. All tables must be part of this DbContext to be part of this transaction
- Where data is to be processed that it is not part of the transaction then it needs to be passed to a handler/service for that part of the data
    - Logging data is not part of Identity and can be passed to a LoggingService
    - Auditing may be part of it there fore the Audit Entity mus be part of the IdentityDbContext and handled as part of the transaction

> **ID-003: relational keys** 
> Required primary and foreign keys shall remain relationally usable. Sensitive natural or composite keys shall be replaced with surrogate keys and verified keyed routing where necessary.

> **ID-004: provider parity** 
> Each supported Identity protection phase shall pass equivalent SQLite and PostgreSQL functional, raw-storage, collision, corruption, concurrency, migration, and recovery tests.

- Correct
- The inherited IdentityDbContext contains the business an d persistence rules associated with this. Therefore the rules will be consistent. The database provider based implementation will handle the persistence

### 11. Failure handling requirements
> **FAIL-001: expected failures**  
> Expected data-plane failures shall use a dependency-free result/union type where the API permits it. Stable failure codes shall cover at least malformed payload, authentication failure, unavailable key, retired key, unsupported profile/version, hash mismatch, ambiguous candidate, size violation, and bounded persistence conflict.

- Correct
- Where Exceptions can be anticipated, with high enough frequency then a result can be returned
- Only edge cases cause excpetions
- Mitigates the use of Exceptions determine application logic

> **FAIL-002: exceptions**  
> Programming errors, invalid startup configuration, cancellation, resource exhaustion, provider failures, and framework boundaries that require exceptions may remain exceptions. Exceptions shall not contain protected values

- Correct
- Always protect data, redact, obfuscate, etc..

> **FAIL-003: no fallback decryption**  
> Failure to resolve or authenticate the selected profile shall not trigger guesses across other algorithms, keys, tenants, properties, or envelope formats.

- Correct
- Data is configured to use the Key and Encryption Manager. All encryption is resolved via this method. 
- If this fails then there is a system/configuration failure
- Guessing will result in errors, wasted time, and the key range is too anstronomically large to even consider brute force 


> **FAIL-004: bounded work**  
> Parsing, candidate verification, database retry, and provider retry shall have explicit bounds. Corrupt or malicious input shall not cause unbounded allocation, unbounded candidate scans, or indefinite retry.

- Correct
- The developer needs to define the bounds of their application.
- The EncryptedIdentityDbContext is the last guard in the processing in mall formed, or invalid data
    _ Models and the DbContext has rules to handle the data size
    - There been a whole data from from client-side t data persistence to catch thiese issues



### 12. Migration and lifecycle requirements
> **MIG-001: conscious operation**  
> Classical-to-PQC, PQC-to-new-PQC, key recovery, and search-key replacement shall be explicit operator-controlled processes with documented availability, backup, replica, export, and rollback consequences.

- Correct
- This is a business decisions for high-availablity or recovery.
    - The breach may be so bad that the systems have to be brought down for security purposes.
    - Or a slow gradual background process may be more appropriate
- It needs to be planned, and trialed
- No automatic process will be developed to do this
- Helper functions to recrypt data will be available, but it is down to the business to implement them


> **MIG-002: per-datum rewrite**  
> Changing the encryption profile or retiring an encryption/KEM key shall decrypt, authenticate, re-protect, and verify every affected datum. Metadata-only key rotation shall not be presented as sufficient.

- Incorrect, this gives the impression that this is an automatic process when changing KeySources
- Handling this is part of the business continuty, disaster recovery process.
- This is the correct process until all the data is confirmed as recrypted. 

> **MIG-003: coexistence**  
> Migration tooling shall permit old and new key handles/profile versions to coexist for a bounded observation period. New writes shall use only the currently active write profile; reads shall resolve all approved historical profiles.

- Correct
- Deactivating and retiring keys will result in all new data being encrypted with active KeySources
- The inactive keys still exist so they can be used to decrypt data 
- This can allow for a staged process of recryption rather than having to stop working

> **MIG-004: staged verification**  
> Migration shall use bounded batches, durable non-secret checkpoints, idempotent retries, full verification, explicit cutover, and separately approved removal of old protected or plaintext data.

- Correct
- This is part of the business' continuity framework. How they want to handle it is down to them
- Migration scripts and data migrations are part of the process that will need to be defined and implemented


> **MIG-005: backups and replicas**  
> Key/profile retirement shall include backups, replicas, exports, caches, queues, and disaster-recovery copies in its plan. A key shall not become irrecoverable while retained data still depends on it.

- Correct
- This is part of a business' data retention and recovery process
- All data they generated that used the Key and Encryption Manager must be tracked.
- Data move from active, to stale, or archived will still have the same keys attached.
- Any data breach that could affect them must be analysed in the context of their data breach policy and acted on acordingly
- Tools will be made available to asist handling the data migration

### **MIG-006: downgrade prevention**  
> A datum protected under a newer required profile shall not be silently rewritten with a weaker or older profile. Any authorized downgrade shall be an explicit audited migration policy.    
- Correct
- No data recryption is automatic, everything is explicit
- The only time existing datq could autmatically be updated is during the life-time fo the data it is updated and it will be updated with a new key, potentialy from one of the new KeySources just added.

### 13. Performance and capacity requirements
> **PERF-001: measurable components** 
> Benchmarks shall separately measure AEAD, KEM encapsulation/decapsulation, key combination/derivation, encoding, database persistence, candidate verification, and complete request workflows.

- Correct
- Performance needs to be gauged against all possible persistence and encryption processes
- The business may be migrating from
    - Single key, default Identity functional
    - Classical encryption from Mrbr 
 - The overhead could affect memory, CPU, network, throughput, storage size, etc.
 - This could affect their desire to implement or if additional resources would be required before implementation

> **PERF-002: realistic distributions** 
> Tests shall cover representative plaintext sizes, candidate counts, entity batch sizes, concurrent writers, connection latency, and both supported database providers.

- Correct
- Performance tests must be representitive to the users own data
- The source code will be MIT, so the user can utilise it in a manner that reflects their own circumstances

> **PERF-003: storage accounting** 
> Capacity planning shall record payload expansion, index size, indirect-row overhead, WAL/log growth, backup growth, replication traffic, and migration working space.

- Correct
- Performance for data size in-flight and in situ needs to be assessed as PQC is considerably larger than classical and un encrypted, as well as PQC data possibly having an associated hash column

> **PERF-004: controlled caching** 
> Caching of public configuration or immutable key metadata may be considered. Plaintext, DEKs, shared secrets, and decapsulated material shall not be cached without a separately approved lifetime and memory-threat model.

- Correct
- This is par of the business' security audit and management
- How they choose to handle configuration and where they store it is their responsibility and choice
- The KeySources may be in multiple places or centrally in a key store. 
    - There security policy will determine the most appropriate location

> **PERF-005: no security bypass** 
> Performance optimizations shall not skip authentication, candidate comparison, domain separation, configuration validation, or required atomic database behavior.

- Correct
- The data mus be tested through the apllication pipeline and data flow. 
- Processing large amount of PQC data could create a bottle neck, or cause overflows due to the size differential of migrating to the new encryption paradigm