namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Parsed representation of a key-handle-prefixed cryptographic artifact.
/// </summary>
/// <param name="KeyHandle">The parsed KeyManager handle.</param>
/// <param name="Artifact">The parsed artifact bytes.</param>
public sealed record KeyedCryptographicArtifact(ulong KeyHandle, byte[] Artifact);
