namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

/// <summary>
/// Declared asymmetric and post-quantum algorithm families.
/// </summary>
/// <remarks>These values are planned surfaces and are not implemented in the current milestone.</remarks>
public enum AsymmetricAlgorithms {
    /// <summary>
    /// RSA public-key encryption and signing. Declared only and not implemented.
    /// </summary>
    RSA = 0,

    /// <summary>
    /// Elliptic curve cryptography. Declared only and not implemented.
    /// </summary>
    ECC = 1,

    /// <summary>
    /// Elliptic Curve Digital Signature Algorithm. Declared only and not implemented.
    /// </summary>
    ECDSA = 2,

    /// <summary>
    /// Ed25519 signature algorithm. Declared only and not implemented.
    /// </summary>
    ED25519 = 3,

    /// <summary>
    /// Module-Lattice-Based Key-Encapsulation Mechanism. Declared only and not implemented.
    /// </summary>
    ML_KEM = 4,

    /// <summary>
    /// Hamming Quasi-Cyclic key encapsulation. Declared only and not implemented.
    /// </summary>
    HQC = 5,

    /// <summary>
    /// Module-Lattice-Based Digital Signature Algorithm. Declared only and not implemented.
    /// </summary>
    ML_DSA = 6,

    /// <summary>
    /// Stateless Hash-Based Digital Signature Algorithm. Declared only and not implemented.
    /// </summary>
    SLH_DSA = 7,

    /// <summary>
    /// Falcon digital signature algorithm. Declared only and not implemented.
    /// </summary>
    FN_DSA = 8
}
