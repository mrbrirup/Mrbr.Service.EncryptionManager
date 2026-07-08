namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Common serialization formats for cryptographic artifacts.
/// </summary>
public enum CryptographicArtifactFormat {
    /// <summary>
    /// Raw artifact bytes.
    /// </summary>
    Raw = 0,

    /// <summary>
    /// Base64-encoded artifact text.
    /// </summary>
    Base64 = 1,

    /// <summary>
    /// Uppercase hexadecimal artifact text.
    /// </summary>
    Hex = 2,

    /// <summary>
    /// ASCII {handle}: followed by raw artifact bytes.
    /// </summary>
    KeyHandleRaw = 3,

    /// <summary>
    /// Text in {handle}:{Base64(artifact)} format.
    /// </summary>
    KeyHandleBase64 = 4,

    /// <summary>
    /// Text in {handle}:{Hex(artifact)} format.
    /// </summary>
    KeyHandleHex = 5
}
