namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

/// <summary>FIPS 203 ML-KEM parameter sets.</summary>
public enum MlKemAlgorithms {
    /// <summary>ML-KEM security category 1 parameter set.</summary>
    MLKEM512 = 1,
    /// <summary>ML-KEM security category 3 parameter set.</summary>
    MLKEM768 = 2,
    /// <summary>ML-KEM security category 5 parameter set.</summary>
    MLKEM1024 = 3
}
