namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Result of an encryption operation.
/// </summary>
/// <param name="KeyHandle">The KeyManager handle required to decrypt the cipher.</param>
/// <param name="Cipher">The AES-GCM cipher artifact in nonce[12] + tag[16] + ciphertext format.</param>
public sealed record EncryptionResult(ulong KeyHandle, byte[] Cipher);
