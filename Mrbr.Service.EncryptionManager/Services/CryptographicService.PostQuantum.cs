using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.EncryptionManager.PostQuantum;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Mrbr.Service.EncryptionManager.Services;

public sealed partial class CryptographicService {
    private static readonly byte[] PqcKdfInfo = "Mrbr.EncryptionManager:ML-KEM:AES-256-GCM:v1"u8.ToArray();

    /// <inheritdoc />
    public EncryptionResult EncryptPostQuantum(byte keySourceId, ReadOnlySpan<byte> dataToEncrypt, PostQuantumEncryptionOptions options) {
        ArgumentNullException.ThrowIfNull(options);
        int seedSize = PostQuantumAlgorithmInfo.GetPrivateSeedSize(options.Algorithm);
        byte[] seed = GC.AllocateUninitializedArray<byte>(seedSize);
        byte[]? sharedSecret = null;
        byte[]? aesKey = null;
        byte[]? associatedData = null;
        try {
            _keyService.GenerateKey(keySourceId, seed, out ulong keyHandle);
            (byte[] encapsulation, sharedSecret) = PostQuantumProvider.Encapsulate(options.Algorithm, seed);
            aesKey = DerivePqcAesKey(sharedSecret);
            associatedData = BuildAssociatedData(keyHandle, options.AssociatedData);

            byte[] protectedData = GC.AllocateUninitializedArray<byte>(PostQuantumAlgorithmInfo.GetProtectedDataSize(options.Algorithm, dataToEncrypt.Length));
            encapsulation.CopyTo(protectedData, 0);
            Span<byte> nonce = protectedData.AsSpan(encapsulation.Length, NonceSizeInBytes);
            Span<byte> tag = protectedData.AsSpan(encapsulation.Length + NonceSizeInBytes, TagSizeInBytes);
            Span<byte> cipher = protectedData.AsSpan(encapsulation.Length + NonceSizeInBytes + TagSizeInBytes);
            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(aesKey, TagSizeInBytes);
            aes.Encrypt(nonce, dataToEncrypt, cipher, tag, associatedData);
            return new EncryptionResult(keyHandle, protectedData);
        }
        finally {
            CryptographicOperations.ZeroMemory(seed);
            if (sharedSecret is not null) CryptographicOperations.ZeroMemory(sharedSecret);
            if (aesKey is not null) CryptographicOperations.ZeroMemory(aesKey);
            if (associatedData is not null) CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    /// <inheritdoc />
    public byte[] DecryptPostQuantum(ulong keyHandle, ReadOnlySpan<byte> protectedData, PostQuantumEncryptionOptions options) {
        ArgumentNullException.ThrowIfNull(options);
        int kemSize = PostQuantumAlgorithmInfo.GetCipherTextSize(options.Algorithm);
        int overhead = checked(kemSize + NonceSizeInBytes + TagSizeInBytes);
        if (protectedData.Length < overhead) throw new ArgumentException("Protected data is truncated.", nameof(protectedData));

        byte[] seed = GC.AllocateUninitializedArray<byte>(PostQuantumAlgorithmInfo.GetPrivateSeedSize(options.Algorithm));
        byte[]? sharedSecret = null;
        byte[]? aesKey = null;
        byte[]? associatedData = null;
        try {
            _keyService.GetKeyBytes(keyHandle, seed);
            sharedSecret = PostQuantumProvider.Decapsulate(options.Algorithm, seed, protectedData[..kemSize]);
            aesKey = DerivePqcAesKey(sharedSecret);
            associatedData = BuildAssociatedData(keyHandle, options.AssociatedData);
            int plainLength = protectedData.Length - overhead;
            byte[] plainText = GC.AllocateUninitializedArray<byte>(plainLength);
            using var aes = new AesGcm(aesKey, TagSizeInBytes);
            aes.Decrypt(
                protectedData.Slice(kemSize, NonceSizeInBytes),
                protectedData[overhead..],
                protectedData.Slice(kemSize + NonceSizeInBytes, TagSizeInBytes),
                plainText,
                associatedData);
            return plainText;
        }
        finally {
            CryptographicOperations.ZeroMemory(seed);
            if (sharedSecret is not null) CryptographicOperations.ZeroMemory(sharedSecret);
            if (aesKey is not null) CryptographicOperations.ZeroMemory(aesKey);
            if (associatedData is not null) CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    /// <inheritdoc />
    public CryptographicResult<byte[]> TryDecryptPostQuantum(ulong keyHandle, ReadOnlySpan<byte> protectedData, PostQuantumEncryptionOptions options) {
        try { return CryptographicResult<byte[]>.Success(DecryptPostQuantum(keyHandle, protectedData, options)); }
        catch (AuthenticationTagMismatchException) { return CryptographicResult<byte[]>.Failed(CryptographicFailure.AuthenticationFailed); }
        catch (ArgumentException) { return CryptographicResult<byte[]>.Failed(CryptographicFailure.InvalidData); }
        catch (KeyNotFoundException) { return CryptographicResult<byte[]>.Failed(CryptographicFailure.KeyUnavailable); }
        catch (InvalidOperationException) { return CryptographicResult<byte[]>.Failed(CryptographicFailure.KeyUnavailable); }
        catch (CryptographicException) { return CryptographicResult<byte[]>.Failed(CryptographicFailure.CryptographicOperationFailed); }
    }

    /// <inheritdoc />
    public SignatureResult SignPostQuantum(byte keySourceId, ReadOnlySpan<byte> dataToSign, PostQuantumSignatureOptions options) {
        ArgumentNullException.ThrowIfNull(options);
        byte[] seed = GC.AllocateUninitializedArray<byte>(PostQuantumAlgorithmInfo.GetPrivateSeedSize(options.Algorithm));
        try {
            _keyService.GenerateKey(keySourceId, seed, out ulong keyHandle);
            return new SignatureResult(keyHandle, PostQuantumProvider.Sign(options.Algorithm, seed, dataToSign));
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    /// <inheritdoc />
    public bool VerifyPostQuantum(ulong keyHandle, ReadOnlySpan<byte> signedData, ReadOnlySpan<byte> signature, PostQuantumSignatureOptions options) {
        ArgumentNullException.ThrowIfNull(options);
        if (signature.Length != PostQuantumAlgorithmInfo.GetSignatureSize(options.Algorithm)) return false;
        byte[] seed = GC.AllocateUninitializedArray<byte>(PostQuantumAlgorithmInfo.GetPrivateSeedSize(options.Algorithm));
        try {
            _keyService.GetKeyBytes(keyHandle, seed);
            return PostQuantumProvider.Verify(options.Algorithm, seed, signedData, signature);
        }
        catch (CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (KeyNotFoundException) { return false; }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    private static byte[] DerivePqcAesKey(ReadOnlySpan<byte> sharedSecret) {
        byte[] output = GC.AllocateUninitializedArray<byte>(32);
        Span<byte> salt = stackalloc byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, output, salt, PqcKdfInfo);
        return output;
    }
}
