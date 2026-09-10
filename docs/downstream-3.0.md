# Downstream adoption: EncryptionManager 3.0.0-preview.1

EncryptionManager now depends on the actual KeyManager 3.0.0-preview.1 package. Downstream projects
have not been modified by this update. Upgrade their dependency graph and run their own tests before
claiming compatibility; an existing 2.0.0 cache entry does not validate this version.

## Confirmed lifecycle contract

KeyManager rejects **new key generation** for disabled/retired sources. Replay remains valid for
decryption, signature/HMAC verification and HmacWithKeyHandle, including new deterministic lookup
inputs. Do not add source-state rejection to deterministic HMAC or searchable-data lookups. This
supersedes earlier review advice suggesting a separate new-use gate for HMAC replay.

EncryptionManager supplies the standard cryptographic operations. Review downstream wrappers and
remove duplicate implementations or pure aliases; call EncryptionManager directly where no extra
behaviour is required. Keep helpers that implement real application semantics, such as normalization,
canonical composite encoding, domain separation, EF value conversion and result adaptation. Those
are not duplicates merely because they invoke a cryptographic operation.

## Encryption.Data / EntityFramework

- Upgrade the EncryptionManager dependency to 3.0.0-preview.1 and resolve the full KeyManager 3 graph.
- Update direct KeyServiceOptions construction in EncryptionManagerEntityDataProtectionServiceTests:
  KeyValidationOptions, persistent source GUIDs, PackedBase64 values and isolated history storage.
- Existing reflection reset names for KeyManager's old static cache no longer work. Keep isolation
  strictly test-only; never expose a production reset/overwrite capability.
- EncryptionManagerEntityDataProtectionService.ComputeSearchHash and ComputeCompositeSearchHash
  currently call HmacWithKeyHandle. Keep that replay usable for disabled/retired sources. Their
  normalization/domain-encoding and result-mapping work is project-specific, not a duplicate HMAC.
- Test lookup, read and decrypt after disabling/retiring a source. New encryption with that source
  must fail; new writes can explicitly select an enabled replacement. Reindexing/re-encryption and
  business approval of source retirement/removal remain application migration concerns.
- Review any pure pass-through crypto aliases when this project is addressed; none were deleted here.

## Encryption.Data.Identity and demos/benchmarks

- Upgrade through the data layer and its transitive dependencies.
- Adapt direct KeyServiceOptions callers in SqliteDemo/Program.cs, BenchmarkProtectionFixture.cs and
  IdentityUserLoadBenchmarks.cs. Use the new options, packed sources and stable GUIDs; history must
  persist for real applications and be isolated for synthetic tests/benchmarks.
- Verify user/role/token/claim/login/passkey reads and deterministic routes remain usable with
  disabled/retired sources. Do not treat retired as unavailable for replay.
- No Identity schema, ciphertext, signature or key-handle format change is introduced by EncryptionManager.
  GUIDs identify configuration generations but are not stored in existing handles.

## KeyEncryptionData.Console and other hosts

- Replace Key and KeyIdMask with KeySourceId and KeyHandleMask; remove SourceFormat. Value is always
  PackedBase64. Persist unique nonempty KeySourceGuid values and allowed lifecycle states.
- Supply KeyValidationOptions with a stable ApplicationId and persistent history directory. First
  enrollment is explicit. Do not regenerate sources/GUIDs or erase validation history on startup.
- KeyServiceOptions.Value, public raw arrays, deletion and text-returning key APIs are gone. Read
  host-owned source selection from application configuration; do not inspect private key storage.
- Submit runtime candidates through Reload or ApplyConfiguration, handle rejection, and retain the
  last accepted configuration. File watching alone does not accept a configuration.
- Consume KeyConfigurationAudit on startup failures and normal operation. Transport, durability,
  retry, independent history comparison, alerting and audit UI are host/downstream responsibilities.
- Business policy determines when migration/backups permit removing a source and reusing an index.
  Replacement needs a new identity and the stopped application's explicit reuse acknowledgement.

## Packaging

Use new package versions rather than overwriting old packages. EncryptionManager retains the same
ICryptographicService signatures; third-party IKeyService implementations need KeyManager 3's
GetSourceState member and must honour its generation/replay contract. Publish compatible serialization
and exception dependency packages alongside the KeyManager release chain. No package was published
by this work.
