using Mrbr.Service.EncryptionManager.Enums.Algorithms;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>Published byte sizes for supported post-quantum algorithms.</summary>
public static class PostQuantumAlgorithmInfo {
    /// <summary>Gets the ML-KEM private seed length.</summary>
    public static int GetPrivateSeedSize(MlKemAlgorithms algorithm) => algorithm switch {
        MlKemAlgorithms.MLKEM512 or MlKemAlgorithms.MLKEM768 or MlKemAlgorithms.MLKEM1024 => 64,
        _ => throw new NotSupportedException($"ML-KEM algorithm '{algorithm}' is not supported.")
    };

    /// <summary>Gets the ML-KEM ciphertext length.</summary>
    public static int GetCipherTextSize(MlKemAlgorithms algorithm) => algorithm switch {
        MlKemAlgorithms.MLKEM512 => 768,
        MlKemAlgorithms.MLKEM768 => 1088,
        MlKemAlgorithms.MLKEM1024 => 1568,
        _ => throw new NotSupportedException($"ML-KEM algorithm '{algorithm}' is not supported.")
    };

    /// <summary>Gets the ML-KEM encapsulation public-key length.</summary>
    public static int GetEncapsulationKeySize(MlKemAlgorithms algorithm) => algorithm switch {
        MlKemAlgorithms.MLKEM512 => 800,
        MlKemAlgorithms.MLKEM768 => 1184,
        MlKemAlgorithms.MLKEM1024 => 1568,
        _ => throw new NotSupportedException($"ML-KEM algorithm '{algorithm}' is not supported.")
    };

    /// <summary>Gets the ML-DSA private seed length.</summary>
    public static int GetPrivateSeedSize(MlDsaAlgorithms algorithm) {
        _ = GetSignatureSize(algorithm);
        return 32;
    }

    /// <summary>Gets the ML-DSA signature length.</summary>
    public static int GetSignatureSize(MlDsaAlgorithms algorithm) => algorithm switch {
        MlDsaAlgorithms.MLDSA44 => 2420,
        MlDsaAlgorithms.MLDSA65 => 3309,
        MlDsaAlgorithms.MLDSA87 => 4627,
        _ => throw new NotSupportedException($"ML-DSA algorithm '{algorithm}' is not supported.")
    };

    /// <summary>Gets the opaque protected-data length for a plaintext length.</summary>
    public static int GetProtectedDataSize(MlKemAlgorithms algorithm, int plainTextSize) {
        ArgumentOutOfRangeException.ThrowIfNegative(plainTextSize);
        return checked(GetCipherTextSize(algorithm) + 12 + 16 + plainTextSize);
    }
}
