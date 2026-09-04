namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>Expected failure categories returned by non-throwing cryptographic operations.</summary>
public enum CryptographicFailure {
    /// <summary>No failure occurred.</summary>
    None = 0,
    /// <summary>The supplied data is malformed or truncated.</summary>
    InvalidData = 1,
    /// <summary>Authentication or integrity validation failed.</summary>
    AuthenticationFailed = 2,
    /// <summary>The requested key material could not be replayed.</summary>
    KeyUnavailable = 3,
    /// <summary>The cryptographic operation failed for another expected reason.</summary>
    CryptographicOperationFailed = 4
}
