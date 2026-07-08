namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

/// <summary>
/// Supported HMAC algorithms.
/// </summary>
public enum HmacAlgorithms {
    /// <summary>
    /// HMAC using SHA-256.
    /// </summary>
    HMACSHA256 = 0,

    /// <summary>
    /// HMAC using SHA-384.
    /// </summary>
    HMACSHA384 = 1,

    /// <summary>
    /// HMAC using SHA-512.
    /// </summary>
    HMACSHA512 = 2
}
