namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Result of an unkeyed hash operation.
/// </summary>
/// <param name="Hash">The computed hash bytes.</param>
public sealed record HashResult(byte[] Hash);
