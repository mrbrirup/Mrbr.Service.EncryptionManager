namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

public enum AsymmetricAlgorithms {
    // Classical Public-Key (Vulnerable to Quantum Attacks)
    RSA = 0,          // Rivest-Shamir-Adleman - Classical encryption and signing
    ECC = 1,          // Elliptic Curve Cryptography - Fast classical math used for encryption keys
    ECDSA = 2,        // Elliptic Curve Digital Signature Algorithm - Current web standard for signing
    ED25519 = 3,      // Edwards-curve Digital Signature Algorithm 25519 - Modern, fast elliptic curve signature

    // Post-Quantum Key Encapsulation (General Encryption)
    ML_KEM = 4,       // Module-Lattice-Based Key-Encapsulation Mechanism - New post-quantum key exchange standard
    HQC = 5,          // Hamming Quasi-Cyclic - Post-quantum backup encryption based on error-correcting codes

    // Post-Quantum Digital Signatures
    ML_DSA = 6,       // Module-Lattice-Based Digital Signature Algorithm - Primary post-quantum signature standard
    SLH_DSA = 7,      // Stateless Hash-Based Digital Signature Algorithm - Slow but highly secure signature backup
    FN_DSA = 8        // Falcon Digital Signature Algorithm - Compact post-quantum signature tool for small devices
}
