using Mrbr.Service.EncryptionManager.Enums.Algorithms;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Options for AES-GCM encryption and decryption.
/// </summary>
public sealed record EncryptionOptions : ICryptographicServiceOptions {
    /// <summary>
    /// Gets the default encryption options.
    /// </summary>
    public static EncryptionOptions Default { get; } = new();

    /// <summary>
    /// Gets the AES key size used for encryption or decryption.
    /// </summary>
    public SymmetricEncryptionAlgorithms Algorithm { get; init; } = SymmetricEncryptionAlgorithms.AES256;

    /// <summary>
    /// Gets caller-provided associated data authenticated by AES-GCM but not included in the cipher artifact.
    /// </summary>
    public ReadOnlyMemory<byte> AssociatedData { get; init; } = ReadOnlyMemory<byte>.Empty;
}
