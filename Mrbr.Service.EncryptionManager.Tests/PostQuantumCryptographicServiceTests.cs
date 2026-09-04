using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.EncryptionManager.PostQuantum;
using Mrbr.Service.EncryptionManager.Services;
using System.Security.Cryptography;

namespace Mrbr.Service.EncryptionManager.Tests;

public partial class CryptographicServiceTests {
    [Theory]
    [InlineData(HashingAlgorithms.SHA3_224, 28)]
    [InlineData(HashingAlgorithms.SHA3_256, 32)]
    [InlineData(HashingAlgorithms.SHA3_384, 48)]
    [InlineData(HashingAlgorithms.SHA3_512, 64)]
    public void Sha3_HashesAndValidates(HashingAlgorithms algorithm, int expectedLength) {
        ICryptographicService service = CreateService();
        var options = new HashOptions { Algorithm = algorithm };
        byte[] data = "sha-3 datum"u8.ToArray();

        HashResult result = service.Hash(data, options);

        Assert.Equal(expectedLength, result.Hash.Length);
        Assert.True(service.ValidateHash(data, result.Hash, options));
        Assert.False(service.ValidateHash("changed"u8.ToArray(), result.Hash, options));
    }

    [Theory]
    [InlineData(HashingAlgorithms.SHAKE128)]
    [InlineData(HashingAlgorithms.SHAKE256)]
    public void Shake_UsesExplicitOutputLength(HashingAlgorithms algorithm) {
        ICryptographicService service = CreateService();
        var options = new HashOptions { Algorithm = algorithm, OutputLengthInBytes = 73 };
        byte[] data = "extendable output datum"u8.ToArray();

        HashResult first = service.Hash(data, options);
        HashResult second = service.Hash(data, options);

        Assert.Equal(73, first.Hash.Length);
        Assert.Equal(first.Hash, second.Hash);
        Assert.True(service.ValidateHash(data, first.Hash, options));
    }

    [Theory]
    [InlineData(HashingAlgorithms.SHAKE128)]
    [InlineData(HashingAlgorithms.SHAKE256)]
    public void Shake_RequiresExplicitPositiveOutputLength(HashingAlgorithms algorithm) {
        ICryptographicService service = CreateService();
        var options = new HashOptions { Algorithm = algorithm };

        Assert.Throws<ArgumentOutOfRangeException>(() => service.Hash("datum"u8.ToArray(), options));
    }

    [Theory]
    [InlineData(MlKemAlgorithms.MLKEM512)]
    [InlineData(MlKemAlgorithms.MLKEM768)]
    [InlineData(MlKemAlgorithms.MLKEM1024)]
    public void PostQuantumEncryption_RoundTrips_AllParameterSets(MlKemAlgorithms algorithm) {
        ICryptographicService service = CreateService();
        var options = new PostQuantumEncryptionOptions(algorithm) { AssociatedData = "entity:property"u8.ToArray() };
        byte[] plainText = "post-quantum protected datum"u8.ToArray();

        EncryptionResult encrypted = service.EncryptPostQuantum(0, plainText, options);
        byte[] decrypted = service.DecryptPostQuantum(encrypted.KeyHandle, encrypted.Cipher, options);

        Assert.Equal(PostQuantumAlgorithmInfo.GetProtectedDataSize(algorithm, plainText.Length), encrypted.Cipher.Length);
        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void PostQuantumEncryption_RejectsTampering() {
        ICryptographicService service = CreateService();
        var options = new PostQuantumEncryptionOptions(MlKemAlgorithms.MLKEM768);
        EncryptionResult encrypted = service.EncryptPostQuantum(0, "protected"u8.ToArray(), options);
        encrypted.Cipher[^1] ^= 1;

        Assert.Throws<AuthenticationTagMismatchException>(
            () => service.DecryptPostQuantum(encrypted.KeyHandle, encrypted.Cipher, options));

        CryptographicResult<byte[]> result = service.TryDecryptPostQuantum(encrypted.KeyHandle, encrypted.Cipher, options);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Equal(CryptographicFailure.AuthenticationFailed, result.Failure);
    }

    [Theory]
    [InlineData(MlDsaAlgorithms.MLDSA44)]
    [InlineData(MlDsaAlgorithms.MLDSA65)]
    [InlineData(MlDsaAlgorithms.MLDSA87)]
    public void PostQuantumSignature_SignsAndVerifies_AllParameterSets(MlDsaAlgorithms algorithm) {
        ICryptographicService service = CreateService();
        var options = new PostQuantumSignatureOptions(algorithm);
        byte[] data = "signed post-quantum datum"u8.ToArray();

        SignatureResult result = service.SignPostQuantum(0, data, options);

        Assert.Equal(PostQuantumAlgorithmInfo.GetSignatureSize(algorithm), result.Signature.Length);
        Assert.True(service.VerifyPostQuantum(result.KeyHandle, data, result.Signature, options));
        Assert.False(service.VerifyPostQuantum(result.KeyHandle, "changed"u8.ToArray(), result.Signature, options));
    }

    [Fact]
    public void MlKem_BouncyCastleSeedReconstruction_IsStable() {
        byte[] seed = RandomNumberGenerator.GetBytes(PostQuantumAlgorithmInfo.GetPrivateSeedSize(MlKemAlgorithms.MLKEM768));
        var result = PostQuantumProvider.BouncyCastleEncapsulate(MlKemAlgorithms.MLKEM768, seed);
        byte[] replayed = PostQuantumProvider.BouncyCastleDecapsulate(MlKemAlgorithms.MLKEM768, seed, result.Encapsulation);
        try { Assert.True(CryptographicOperations.FixedTimeEquals(result.SharedSecret, replayed)); }
        finally {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(result.SharedSecret);
            CryptographicOperations.ZeroMemory(replayed);
        }
    }

    [Fact]
    public void NativeAndBouncyCastleMlKem_AreInteroperable_WhenNativeIsAvailable() {
        if (!PostQuantumProvider.NativeMlKemAvailable) return;
        byte[] seed = RandomNumberGenerator.GetBytes(PostQuantumAlgorithmInfo.GetPrivateSeedSize(MlKemAlgorithms.MLKEM768));
        var native = PostQuantumProvider.NativeEncapsulate(MlKemAlgorithms.MLKEM768, seed);
        byte[] bcSecret = PostQuantumProvider.BouncyCastleDecapsulate(MlKemAlgorithms.MLKEM768, seed, native.Encapsulation);
        var bc = PostQuantumProvider.BouncyCastleEncapsulate(MlKemAlgorithms.MLKEM768, seed);
        byte[] nativeSecret = PostQuantumProvider.NativeDecapsulate(MlKemAlgorithms.MLKEM768, seed, bc.Encapsulation);
        try {
            Assert.True(CryptographicOperations.FixedTimeEquals(native.SharedSecret, bcSecret));
            Assert.True(CryptographicOperations.FixedTimeEquals(bc.SharedSecret, nativeSecret));
        }
        finally {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(native.SharedSecret);
            CryptographicOperations.ZeroMemory(bcSecret);
            CryptographicOperations.ZeroMemory(bc.SharedSecret);
            CryptographicOperations.ZeroMemory(nativeSecret);
        }
    }

    [Fact]
    public void NativeAndBouncyCastleMlDsa_AreInteroperable_WhenNativeIsAvailable() {
        if (!PostQuantumProvider.NativeMlDsaAvailable) return;
        byte[] seed = RandomNumberGenerator.GetBytes(PostQuantumAlgorithmInfo.GetPrivateSeedSize(MlDsaAlgorithms.MLDSA65));
        byte[] data = "provider interoperability"u8.ToArray();
        try {
            byte[] nativeSignature = PostQuantumProvider.NativeSign(MlDsaAlgorithms.MLDSA65, seed, data);
            byte[] bcSignature = PostQuantumProvider.BouncyCastleSign(MlDsaAlgorithms.MLDSA65, seed, data);
            Assert.True(PostQuantumProvider.BouncyCastleVerify(MlDsaAlgorithms.MLDSA65, seed, data, nativeSignature));
            Assert.True(PostQuantumProvider.NativeVerify(MlDsaAlgorithms.MLDSA65, seed, data, bcSignature));
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
}
