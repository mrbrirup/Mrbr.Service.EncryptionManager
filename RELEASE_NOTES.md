# Release notes

## 3.0.0-preview.1 : 2026-09-10

Adopts KeyManager 3.0.0-preview.1 and its breaking configuration/lifecycle contract. Major version
3 communicates the required host/configuration upgrade; preview status matches the .NET 11 target
and KeyManager dependency. Public cryptographic method signatures and artefact layouts are unchanged.

- Upgraded all KeyManager package references, including tests and console, to 3.0.0-preview.1.
- New-key operations rely on KeyManager to reject disabled/retired sources. Existing-key replay
  remains available for decryption, verification and deterministic HMAC, even with new lookup inputs.
  No extra new-use restriction was added to HmacWithKeyHandle.
- Updated console registration for KeyValidationOptions and strict deferred configuration loading.
  Added explicit enrollment, config/history/source selection, no-overwrite demo generation, sanitized
  startup failure handling and queued audit consumption. Removed use of KeyServiceOptions.Value.
- Replaced legacy console sample with disposable PackedBase64/GUID configuration. Published demo
  values must never protect real data.
- Updated real-KeyManager fixtures for packed sources, GUIDs and isolated history. Added Block and
  Matrix lifecycle tests, both buffer/allocated replay paths, deterministic HMAC lookups, PQC signing
  and verification, re-enabling, irreversible retirement, explicit source rotation, and rejected updates.
- Updated README, XML API contract documentation and downstream adoption checklist; release notes
  and checklist are included in the NuGet package.

Verification: Release solution build without warnings, 80 passing tests. No NuGet publication is
performed. See [downstream adoption](docs/downstream-3.0.md) before upgrading consuming projects.

Remaining work: downstream host/configuration upgrades, review of redundant cryptographic wrappers,
and the separately tracked KeyManager derivation-options/public-release readiness items. This update
does not migrate stored data or introduce external audit transport, comparison services or UI.
