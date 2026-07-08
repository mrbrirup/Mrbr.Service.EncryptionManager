namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

/// <summary>
/// Declared hashing algorithms.
/// </summary>
/// <remarks>Only SHA256, SHA384, and SHA512 are implemented in the current milestone.</remarks>
public enum HashingAlgorithms {
    /// <summary>
    /// Message Digest 5. Declared only and not implemented; do not use for cryptographic security.
    /// </summary>
    MD5 = 0,

    /// <summary>
    /// Secure Hash Algorithm 0. Declared only and not implemented; do not use for cryptographic security.
    /// </summary>
    SHA0 = 1,

    /// <summary>
    /// Secure Hash Algorithm 1. Declared only and not implemented; do not use for cryptographic security.
    /// </summary>
    SHA1 = 2,

    /// <summary>
    /// SHA-2 with a 224-bit digest. Declared only and not implemented.
    /// </summary>
    SHA224 = 3,

    /// <summary>
    /// SHA-2 with a 256-bit digest.
    /// </summary>
    SHA256 = 4,

    /// <summary>
    /// SHA-2 with a 384-bit digest.
    /// </summary>
    SHA384 = 5,

    /// <summary>
    /// SHA-2 with a 512-bit digest.
    /// </summary>
    SHA512 = 6,

    /// <summary>
    /// SHA-2 with a 224-bit digest truncated from SHA-512. Declared only and not implemented.
    /// </summary>
    SHA512_224 = 7,

    /// <summary>
    /// SHA-2 with a 256-bit digest truncated from SHA-512. Declared only and not implemented.
    /// </summary>
    SHA512_256 = 8,

    /// <summary>
    /// SHA-3 with a 224-bit digest. Declared only and not implemented.
    /// </summary>
    SHA3_224 = 9,

    /// <summary>
    /// SHA-3 with a 256-bit digest. Declared only and not implemented.
    /// </summary>
    SHA3_256 = 10,

    /// <summary>
    /// SHA-3 with a 384-bit digest. Declared only and not implemented.
    /// </summary>
    SHA3_384 = 11,

    /// <summary>
    /// SHA-3 with a 512-bit digest. Declared only and not implemented.
    /// </summary>
    SHA3_512 = 12,

    /// <summary>
    /// SHAKE128 variable-length output function. Declared only and not implemented.
    /// </summary>
    SHAKE128 = 13,

    /// <summary>
    /// SHAKE256 variable-length output function. Declared only and not implemented.
    /// </summary>
    SHAKE256 = 14,

    /// <summary>
    /// BLAKE3 hashing. Declared only and not implemented.
    /// </summary>
    BLAKE3 = 15
}
