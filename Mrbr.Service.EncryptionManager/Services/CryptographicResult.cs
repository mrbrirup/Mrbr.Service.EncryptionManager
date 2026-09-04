namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>A value or a known cryptographic failure without exception-driven control flow.</summary>
public readonly record struct CryptographicResult<T>(T? Value, CryptographicFailure Failure) where T : class {
    /// <summary>Gets whether the operation produced a value.</summary>
    public bool IsSuccess => Failure == CryptographicFailure.None;

    /// <summary>Creates a successful result.</summary>
    public static CryptographicResult<T> Success(T value) => new(value, CryptographicFailure.None);

    /// <summary>Creates a failed result.</summary>
    public static CryptographicResult<T> Failed(CryptographicFailure failure) {
        if (failure == CryptographicFailure.None) throw new ArgumentOutOfRangeException(nameof(failure));
        return new CryptographicResult<T>(null, failure);
    }
}
