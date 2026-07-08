namespace Mrbr.Service.EncryptionManager.Enums.Algorithms;

/// <summary>
/// Supported symmetric encryption key sizes.
/// </summary>
public enum SymmetricEncryptionAlgorithms {
    /// <summary>
    /// AES-GCM with a 128-bit key.
    /// </summary>
    AES128 = 0,

    /// <summary>
    /// AES-GCM with a 192-bit key.
    /// </summary>
    AES192 = 1,

    /// <summary>
    /// AES-GCM with a 256-bit key.
    /// </summary>
    AES256 = 2
}
