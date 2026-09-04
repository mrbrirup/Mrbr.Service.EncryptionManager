namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>A KeyManager replay handle and its signature bytes.</summary>
public sealed record SignatureResult(ulong KeyHandle, byte[] Signature);
