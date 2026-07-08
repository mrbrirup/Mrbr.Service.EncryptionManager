namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Result of an HMAC operation.
/// </summary>
/// <param name="KeyHandle">The KeyManager handle required to validate the HMAC.</param>
/// <param name="Hmac">The computed HMAC bytes.</param>
public sealed record HmacResult(ulong KeyHandle, byte[] Hmac);
