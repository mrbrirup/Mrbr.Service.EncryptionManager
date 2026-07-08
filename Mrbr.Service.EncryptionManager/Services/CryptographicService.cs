using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.KeyManager.Services;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Default implementation of <see cref="ICryptographicService" />.
/// </summary>
/// <param name="keyService">The KeyManager service used to generate and replay key material.</param>
public sealed class CryptographicService(IKeyService keyService) : ICryptographicService {
    private const int NonceSizeInBytes = 12;
    private const int TagSizeInBytes = 16;
    private const int KeyHandleSizeInBytes = sizeof(ulong);

    private readonly IKeyService _keyService = keyService ?? throw new ArgumentNullException(nameof(keyService));

    /// <inheritdoc />
    public EncryptionResult Encrypt(ReadOnlySpan<byte> dataToEncrypt, EncryptionOptions? encryptionOptions = null) {
        var options = ResolveEncryptionOptions(encryptionOptions);
        byte[] cipher = GC.AllocateUninitializedArray<byte>(GetCipherLength(dataToEncrypt.Length));
        Encrypt(dataToEncrypt, cipher, out ulong keyHandle, options);
        return new EncryptionResult(keyHandle, cipher);
    }

    /// <inheritdoc />
    public int Encrypt(
        ReadOnlySpan<byte> dataToEncrypt,
        Span<byte> cipherDestination,
        out ulong keyHandle,
        EncryptionOptions? encryptionOptions = null) {
        EnsureAesGcmSupported();

        var options = ResolveEncryptionOptions(encryptionOptions);
        int cipherLength = GetCipherLength(dataToEncrypt.Length);
        if (cipherDestination.Length < cipherLength) {
            throw new ArgumentException($"Destination must be at least {cipherLength} bytes.", nameof(cipherDestination));
        }

        int keySize = GetKeySizeInBytes(options.Algorithm);
        Span<byte> key = stackalloc byte[keySize];
        byte[]? associatedData = null;
        try {
            GenerateKey(options.Algorithm, key, out keyHandle);
            associatedData = BuildAssociatedData(keyHandle, options.AssociatedData);

            Span<byte> nonce = cipherDestination.Slice(0, NonceSizeInBytes);
            Span<byte> tag = cipherDestination.Slice(NonceSizeInBytes, TagSizeInBytes);
            Span<byte> cipherText = cipherDestination.Slice(NonceSizeInBytes + TagSizeInBytes, dataToEncrypt.Length);

            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(key, TagSizeInBytes);
            aes.Encrypt(nonce, dataToEncrypt, cipherText, tag, associatedData);
            return cipherLength;
        }
        finally {
            CryptographicOperations.ZeroMemory(key);
            if (associatedData is not null) {
                CryptographicOperations.ZeroMemory(associatedData);
            }
        }
    }

    /// <inheritdoc />
    public byte[] Decrypt(ulong keyHandle, ReadOnlySpan<byte> cipher, EncryptionOptions? encryptionOptions = null) {
        int plainTextLength = GetPlainTextLength(cipher.Length);
        byte[] plainText = GC.AllocateUninitializedArray<byte>(plainTextLength);
        Decrypt(keyHandle, cipher, plainText, encryptionOptions);
        return plainText;
    }

    /// <inheritdoc />
    public int Decrypt(
        ulong keyHandle,
        ReadOnlySpan<byte> cipher,
        Span<byte> plainTextDestination,
        EncryptionOptions? encryptionOptions = null) {
        EnsureAesGcmSupported();

        var options = ResolveEncryptionOptions(encryptionOptions);
        int plainTextLength = GetPlainTextLength(cipher.Length);
        if (plainTextDestination.Length < plainTextLength) {
            throw new ArgumentException($"Destination must be at least {plainTextLength} bytes.", nameof(plainTextDestination));
        }

        int keySize = GetKeySizeInBytes(options.Algorithm);
        Span<byte> key = stackalloc byte[keySize];
        byte[]? associatedData = null;
        try {
            GetKey(options.Algorithm, keyHandle, key);
            associatedData = BuildAssociatedData(keyHandle, options.AssociatedData);

            ReadOnlySpan<byte> nonce = cipher.Slice(0, NonceSizeInBytes);
            ReadOnlySpan<byte> tag = cipher.Slice(NonceSizeInBytes, TagSizeInBytes);
            ReadOnlySpan<byte> cipherText = cipher.Slice(NonceSizeInBytes + TagSizeInBytes, plainTextLength);

            using var aes = new AesGcm(key, TagSizeInBytes);
            aes.Decrypt(nonce, cipherText, tag, plainTextDestination.Slice(0, plainTextLength), associatedData);
            return plainTextLength;
        }
        finally {
            CryptographicOperations.ZeroMemory(key);
            if (associatedData is not null) {
                CryptographicOperations.ZeroMemory(associatedData);
            }
        }
    }

    /// <inheritdoc />
    public string EncryptText(string plainText, EncryptionOptions? encryptionOptions = null) {
        ArgumentNullException.ThrowIfNull(plainText);

        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        try {
            var result = Encrypt(plainTextBytes, encryptionOptions);
            return CryptographicArtifactSerializer.ToKeyHandleBase64(result.KeyHandle, result.Cipher);
        }
        finally {
            CryptographicOperations.ZeroMemory(plainTextBytes);
        }
    }

    /// <inheritdoc />
    public string DecryptText(string encryptedText, EncryptionOptions? encryptionOptions = null) {
        var artifact = CryptographicArtifactSerializer.FromKeyHandleBase64(encryptedText);
        byte[] plainTextBytes = Decrypt(artifact.KeyHandle, artifact.Artifact, encryptionOptions);
        try {
            return Encoding.UTF8.GetString(plainTextBytes);
        }
        finally {
            CryptographicOperations.ZeroMemory(plainTextBytes);
        }
    }

    /// <inheritdoc />
    public HashResult Hash(ReadOnlySpan<byte> dataToHash, HashOptions? hashOptions = null) {
        var options = ResolveHashOptions(hashOptions);
        byte[] hash = GC.AllocateUninitializedArray<byte>(GetHashLength(options.Algorithm));
        Hash(dataToHash, hash, options);
        return new HashResult(hash);
    }

    /// <inheritdoc />
    public int Hash(ReadOnlySpan<byte> dataToHash, Span<byte> hashDestination, HashOptions? hashOptions = null) {
        var options = ResolveHashOptions(hashOptions);
        int hashLength = GetHashLength(options.Algorithm);
        if (hashDestination.Length < hashLength) {
            throw new ArgumentException($"Destination must be at least {hashLength} bytes.", nameof(hashDestination));
        }

        return WriteHash(options.Algorithm, dataToHash, hashDestination);
    }

    /// <inheritdoc />
    public bool ValidateHash(ReadOnlySpan<byte> dataToHash, ReadOnlySpan<byte> expectedHash, HashOptions? hashOptions = null) {
        var options = ResolveHashOptions(hashOptions);
        int hashLength = GetHashLength(options.Algorithm);
        if (expectedHash.Length != hashLength) {
            return false;
        }

        Span<byte> computedHash = stackalloc byte[hashLength];
        try {
            WriteHash(options.Algorithm, dataToHash, computedHash);
            return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
        }
        finally {
            CryptographicOperations.ZeroMemory(computedHash);
        }
    }

    /// <inheritdoc />
    public HmacResult Hmac(ReadOnlySpan<byte> dataToAuthenticate, HmacOptions? hmacOptions = null) {
        var options = ResolveHmacOptions(hmacOptions);
        byte[] hmac = GC.AllocateUninitializedArray<byte>(GetHmacLength(options.Algorithm));
        Hmac(dataToAuthenticate, hmac, out ulong keyHandle, options);
        return new HmacResult(keyHandle, hmac);
    }

    /// <inheritdoc />
    public int Hmac(
        ReadOnlySpan<byte> dataToAuthenticate,
        Span<byte> hmacDestination,
        out ulong keyHandle,
        HmacOptions? hmacOptions = null) {
        var options = ResolveHmacOptions(hmacOptions);
        int hmacLength = GetHmacLength(options.Algorithm);
        if (hmacDestination.Length < hmacLength) {
            throw new ArgumentException($"Destination must be at least {hmacLength} bytes.", nameof(hmacDestination));
        }

        int keySize = GetKeySizeInBytes(options.KeySizeInBits);
        Span<byte> key = stackalloc byte[keySize];
        try {
            GenerateKey(options.KeySizeInBits, key, out keyHandle);
            return WriteHmac(options.Algorithm, key, dataToAuthenticate, hmacDestination);
        }
        finally {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    public bool ValidateHmac(
        ulong keyHandle,
        ReadOnlySpan<byte> authenticatedData,
        ReadOnlySpan<byte> expectedHmac,
        HmacOptions? hmacOptions = null) {
        var options = ResolveHmacOptions(hmacOptions);
        int hmacLength = GetHmacLength(options.Algorithm);
        int keySize = GetKeySizeInBytes(options.KeySizeInBits);
        if (expectedHmac.Length != hmacLength) {
            return false;
        }

        Span<byte> key = stackalloc byte[keySize];
        Span<byte> computedHmac = stackalloc byte[hmacLength];
        try {
            GetKey(options.KeySizeInBits, keyHandle, key);
            WriteHmac(options.Algorithm, key, authenticatedData, computedHmac);
            return CryptographicOperations.FixedTimeEquals(computedHmac, expectedHmac);
        }
        catch (ArgumentException) {
            return false;
        }
        catch (InvalidOperationException) {
            return false;
        }
        catch (KeyNotFoundException) {
            return false;
        }
        finally {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(computedHmac);
        }
    }

    /// <summary>
    /// Gets the required AES-GCM artifact length for a plaintext length.
    /// </summary>
    /// <param name="plainTextLength">The plaintext length in bytes.</param>
    /// <returns>The cipher artifact length in bytes.</returns>
    public static int GetCipherLength(int plainTextLength) {
        if (plainTextLength < 0) {
            throw new ArgumentOutOfRangeException(nameof(plainTextLength), "Plain text length cannot be negative.");
        }

        return checked(NonceSizeInBytes + TagSizeInBytes + plainTextLength);
    }

    /// <summary>
    /// Gets the plaintext length represented by an AES-GCM cipher artifact length.
    /// </summary>
    /// <param name="cipherLength">The cipher artifact length in bytes.</param>
    /// <returns>The plaintext length in bytes.</returns>
    public static int GetPlainTextLength(int cipherLength) {
        if (cipherLength < NonceSizeInBytes + TagSizeInBytes) {
            throw new ArgumentException($"Cipher artifact must be at least {NonceSizeInBytes + TagSizeInBytes} bytes.", nameof(cipherLength));
        }

        return cipherLength - NonceSizeInBytes - TagSizeInBytes;
    }

    /// <summary>
    /// Gets the hash length for a supported hash algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The hash length in bytes.</returns>
    public static int GetHashLength(HashingAlgorithms algorithm) =>
        algorithm switch {
            HashingAlgorithms.SHA256 => 32,
            HashingAlgorithms.SHA384 => 48,
            HashingAlgorithms.SHA512 => 64,
            _ => throw new NotSupportedException($"Hashing algorithm '{algorithm}' is not supported.")
        };

    /// <summary>
    /// Gets the HMAC length for a supported HMAC algorithm.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <returns>The HMAC length in bytes.</returns>
    public static int GetHmacLength(HmacAlgorithms algorithm) =>
        algorithm switch {
            HmacAlgorithms.HMACSHA256 => 32,
            HmacAlgorithms.HMACSHA384 => 48,
            HmacAlgorithms.HMACSHA512 => 64,
            _ => throw new NotSupportedException($"HMAC algorithm '{algorithm}' is not supported.")
        };

    private static EncryptionOptions ResolveEncryptionOptions(EncryptionOptions? encryptionOptions) =>
        encryptionOptions is null
            ? EncryptionOptions.Default
            : new EncryptionOptions {
                Algorithm = encryptionOptions.Algorithm,
                AssociatedData = encryptionOptions.AssociatedData
            };

    private static HashOptions ResolveHashOptions(HashOptions? hashOptions) =>
        hashOptions is null
            ? HashOptions.Default
            : new HashOptions {
                Algorithm = hashOptions.Algorithm
            };

    private static HmacOptions ResolveHmacOptions(HmacOptions? hmacOptions) =>
        hmacOptions is null
            ? HmacOptions.Default
            : new HmacOptions {
                Algorithm = hmacOptions.Algorithm,
                KeySizeInBits = hmacOptions.KeySizeInBits
            };

    private void GenerateKey(SymmetricEncryptionAlgorithms algorithm, Span<byte> destination, out ulong keyHandle) {
        switch (algorithm) {
            case SymmetricEncryptionAlgorithms.AES128:
                _keyService.GenerateKey128(destination, out keyHandle);
                return;
            case SymmetricEncryptionAlgorithms.AES192:
                _keyService.GenerateKey192(destination, out keyHandle);
                return;
            case SymmetricEncryptionAlgorithms.AES256:
                _keyService.GenerateKey256(destination, out keyHandle);
                return;
            default:
                throw new NotSupportedException($"Symmetric algorithm '{algorithm}' is not supported.");
        }
    }

    private void GenerateKey(int keySizeInBits, Span<byte> destination, out ulong keyHandle) {
        switch (keySizeInBits) {
            case 128:
                _keyService.GenerateKey128(destination, out keyHandle);
                return;
            case 192:
                _keyService.GenerateKey192(destination, out keyHandle);
                return;
            case 256:
                _keyService.GenerateKey256(destination, out keyHandle);
                return;
            default:
                throw new NotSupportedException($"Key material size '{keySizeInBits}' is not supported.");
        }
    }

    private void GetKey(SymmetricEncryptionAlgorithms algorithm, ulong keyHandle, Span<byte> destination) {
        switch (algorithm) {
            case SymmetricEncryptionAlgorithms.AES128:
                _keyService.GetKey128(keyHandle, destination);
                return;
            case SymmetricEncryptionAlgorithms.AES192:
                _keyService.GetKey192(keyHandle, destination);
                return;
            case SymmetricEncryptionAlgorithms.AES256:
                _keyService.GetKey256(keyHandle, destination);
                return;
            default:
                throw new NotSupportedException($"Symmetric algorithm '{algorithm}' is not supported.");
        }
    }

    private void GetKey(int keySizeInBits, ulong keyHandle, Span<byte> destination) {
        switch (keySizeInBits) {
            case 128:
                _keyService.GetKey128(keyHandle, destination);
                return;
            case 192:
                _keyService.GetKey192(keyHandle, destination);
                return;
            case 256:
                _keyService.GetKey256(keyHandle, destination);
                return;
            default:
                throw new NotSupportedException($"Key material size '{keySizeInBits}' is not supported.");
        }
    }

    private static int GetKeySizeInBytes(SymmetricEncryptionAlgorithms algorithm) =>
        algorithm switch {
            SymmetricEncryptionAlgorithms.AES128 => 16,
            SymmetricEncryptionAlgorithms.AES192 => 24,
            SymmetricEncryptionAlgorithms.AES256 => 32,
            _ => throw new NotSupportedException($"Symmetric algorithm '{algorithm}' is not supported.")
        };

    private static int GetKeySizeInBytes(int keySizeInBits) =>
        keySizeInBits switch {
            128 => 16,
            192 => 24,
            256 => 32,
            _ => throw new NotSupportedException($"Key size '{keySizeInBits}' is not supported.")
        };

    private static int WriteHash(HashingAlgorithms algorithm, ReadOnlySpan<byte> data, Span<byte> destination) =>
        algorithm switch {
            HashingAlgorithms.SHA256 => SHA256.HashData(data, destination),
            HashingAlgorithms.SHA384 => SHA384.HashData(data, destination),
            HashingAlgorithms.SHA512 => SHA512.HashData(data, destination),
            _ => throw new NotSupportedException($"Hashing algorithm '{algorithm}' is not supported.")
        };

    private static int WriteHmac(
        HmacAlgorithms algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data,
        Span<byte> destination) =>
        algorithm switch {
            HmacAlgorithms.HMACSHA256 => HMACSHA256.HashData(key, data, destination),
            HmacAlgorithms.HMACSHA384 => HMACSHA384.HashData(key, data, destination),
            HmacAlgorithms.HMACSHA512 => HMACSHA512.HashData(key, data, destination),
            _ => throw new NotSupportedException($"HMAC algorithm '{algorithm}' is not supported.")
        };

    private static byte[] BuildAssociatedData(ulong keyHandle, ReadOnlyMemory<byte> additionalData) {
        byte[] associatedData = GC.AllocateUninitializedArray<byte>(KeyHandleSizeInBytes + additionalData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(associatedData.AsSpan(0, KeyHandleSizeInBytes), keyHandle);
        additionalData.Span.CopyTo(associatedData.AsSpan(KeyHandleSizeInBytes));
        return associatedData;
    }

    private static void EnsureAesGcmSupported() {
        if (AesGcm.IsSupported == false) {
            throw new PlatformNotSupportedException("AES-GCM is not supported on this platform.");
        }
    }
}
