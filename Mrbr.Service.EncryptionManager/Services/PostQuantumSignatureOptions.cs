using Mrbr.Service.EncryptionManager.Enums.Algorithms;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>Explicit settings for an ML-DSA signature.</summary>
public sealed record PostQuantumSignatureOptions {
    /// <summary>Creates options for an explicit ML-DSA parameter set.</summary>
    public PostQuantumSignatureOptions(MlDsaAlgorithms algorithm) => Algorithm = algorithm;
    /// <summary>Gets the ML-DSA parameter set.</summary>
    public MlDsaAlgorithms Algorithm { get; }
}
