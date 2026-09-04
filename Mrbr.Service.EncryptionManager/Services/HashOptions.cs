using Mrbr.Service.EncryptionManager.Enums.Algorithms;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Options for unkeyed hash operations.
/// </summary>
public sealed record HashOptions : ICryptographicServiceOptions {
    /// <summary>
    /// Gets the default hash options.
    /// </summary>
    public static HashOptions Default { get; } = new();

    /// <summary>
    /// Gets the hash algorithm.
    /// </summary>
    public HashingAlgorithms Algorithm { get; init; } = HashingAlgorithms.SHA256;

    /// <summary>Gets the requested output length for SHAKE128 or SHAKE256.</summary>
    public int? OutputLengthInBytes { get; init; }
}
