using Mrbr.Service.EncryptionManager.Enums.Algorithms;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>Explicit settings for ML-KEM plus AES-256-GCM data protection.</summary>
public sealed record PostQuantumEncryptionOptions {
    /// <summary>Creates options for an explicit ML-KEM parameter set.</summary>
    public PostQuantumEncryptionOptions(MlKemAlgorithms algorithm) => Algorithm = algorithm;
    /// <summary>Gets the ML-KEM parameter set.</summary>
    public MlKemAlgorithms Algorithm { get; }
    /// <summary>Gets caller data authenticated but not stored in the protected bytes.</summary>
    public ReadOnlyMemory<byte> AssociatedData { get; init; } = ReadOnlyMemory<byte>.Empty;
}
