using Mrbr.Service.EncryptionManager.Enums.Algorithms;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Options for HMAC operations.
/// </summary>
/// <remarks>The HMAC is computed over exactly the bytes supplied to the HMAC method.</remarks>
public sealed record HmacOptions : ICryptographicServiceOptions {
    /// <summary>
    /// Gets the default HMAC options.
    /// </summary>
    public static HmacOptions Default { get; } = new();

    /// <summary>
    /// Gets the HMAC algorithm.
    /// </summary>
    public HmacAlgorithms Algorithm { get; init; } = HmacAlgorithms.HMACSHA256;

    /// <summary>
    /// Gets the KeyManager key material size for HMAC operations.
    /// </summary>
    /// <remarks>Supported values are 128, 192, and 256.</remarks>
    public int KeySizeInBits { get; init; } = 256;
}
