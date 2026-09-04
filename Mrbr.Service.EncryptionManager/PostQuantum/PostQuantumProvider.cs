using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;

namespace Mrbr.Service.EncryptionManager.PostQuantum;

internal static class PostQuantumProvider {
    internal static bool NativeMlKemAvailable => MLKem.IsSupported;
    internal static bool NativeMlDsaAvailable => MLDsa.IsSupported;

    internal static (byte[] Encapsulation, byte[] SharedSecret) Encapsulate(MlKemAlgorithms algorithm, ReadOnlySpan<byte> seed) =>
        NativeMlKemAvailable ? NativeEncapsulate(algorithm, seed) : BouncyCastleEncapsulate(algorithm, seed);

    internal static byte[] Decapsulate(MlKemAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> encapsulation) =>
        NativeMlKemAvailable ? NativeDecapsulate(algorithm, seed, encapsulation) : BouncyCastleDecapsulate(algorithm, seed, encapsulation);

    internal static byte[] Sign(MlDsaAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data) =>
        NativeMlDsaAvailable ? NativeSign(algorithm, seed, data) : BouncyCastleSign(algorithm, seed, data);

    internal static bool Verify(MlDsaAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        NativeMlDsaAvailable ? NativeVerify(algorithm, seed, data, signature) : BouncyCastleVerify(algorithm, seed, data, signature);

    internal static (byte[] Encapsulation, byte[] SharedSecret) NativeEncapsulate(MlKemAlgorithms algorithm, ReadOnlySpan<byte> seed) {
        using MLKem privateKey = MLKem.ImportPrivateSeed(GetNative(algorithm), seed);
        using MLKem publicKey = MLKem.ImportEncapsulationKey(GetNative(algorithm), privateKey.ExportEncapsulationKey());
        publicKey.Encapsulate(out byte[] encapsulation, out byte[] sharedSecret);
        return (encapsulation, sharedSecret);
    }

    internal static byte[] NativeDecapsulate(MlKemAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> encapsulation) {
        using MLKem privateKey = MLKem.ImportPrivateSeed(GetNative(algorithm), seed);
        return privateKey.Decapsulate(encapsulation.ToArray());
    }

    internal static (byte[] Encapsulation, byte[] SharedSecret) BouncyCastleEncapsulate(MlKemAlgorithms algorithm, ReadOnlySpan<byte> seed) {
        MLKemParameters parameters = GetBouncyCastle(algorithm);
        MLKemPrivateKeyParameters privateKey = MLKemPrivateKeyParameters.FromSeed(parameters, seed.ToArray());
        var encapsulator = new MLKemEncapsulator(parameters);
        encapsulator.Init(privateKey.GetPublicKey());
        byte[] encapsulation = new byte[encapsulator.EncapsulationLength];
        byte[] sharedSecret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(encapsulation, 0, encapsulation.Length, sharedSecret, 0, sharedSecret.Length);
        return (encapsulation, sharedSecret);
    }

    internal static byte[] BouncyCastleDecapsulate(MlKemAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> encapsulation) {
        MLKemParameters parameters = GetBouncyCastle(algorithm);
        MLKemPrivateKeyParameters privateKey = MLKemPrivateKeyParameters.FromSeed(parameters, seed.ToArray());
        var decapsulator = new MLKemDecapsulator(parameters);
        decapsulator.Init(privateKey);
        byte[] sharedSecret = new byte[decapsulator.SecretLength];
        byte[] input = encapsulation.ToArray();
        decapsulator.Decapsulate(input, 0, input.Length, sharedSecret, 0, sharedSecret.Length);
        return sharedSecret;
    }

    internal static byte[] NativeSign(MlDsaAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data) {
        using MLDsa key = MLDsa.ImportMLDsaPrivateSeed(GetNative(algorithm), seed);
        return key.SignData(data.ToArray());
    }

    internal static bool NativeVerify(MlDsaAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) {
        using MLDsa key = MLDsa.ImportMLDsaPrivateSeed(GetNative(algorithm), seed);
        return key.VerifyData(data.ToArray(), signature.ToArray());
    }

    internal static byte[] BouncyCastleSign(MlDsaAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data) {
        MLDsaParameters parameters = GetBouncyCastle(algorithm);
        MLDsaPrivateKeyParameters privateKey = MLDsaPrivateKeyParameters.FromSeed(parameters, seed.ToArray());
        var signer = new MLDsaSigner(parameters, deterministic: true);
        signer.Init(true, privateKey);
        byte[] input = data.ToArray();
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    internal static bool BouncyCastleVerify(MlDsaAlgorithms algorithm, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) {
        MLDsaParameters parameters = GetBouncyCastle(algorithm);
        MLDsaPrivateKeyParameters privateKey = MLDsaPrivateKeyParameters.FromSeed(parameters, seed.ToArray());
        var verifier = new MLDsaSigner(parameters, deterministic: true);
        verifier.Init(false, privateKey.GetPublicKey());
        byte[] input = data.ToArray();
        verifier.BlockUpdate(input, 0, input.Length);
        return verifier.VerifySignature(signature.ToArray());
    }

    private static MLKemAlgorithm GetNative(MlKemAlgorithms algorithm) => algorithm switch {
        MlKemAlgorithms.MLKEM512 => MLKemAlgorithm.MLKem512,
        MlKemAlgorithms.MLKEM768 => MLKemAlgorithm.MLKem768,
        MlKemAlgorithms.MLKEM1024 => MLKemAlgorithm.MLKem1024,
        _ => throw new NotSupportedException($"ML-KEM algorithm '{algorithm}' is not supported.")
    };

    private static MLKemParameters GetBouncyCastle(MlKemAlgorithms algorithm) => algorithm switch {
        MlKemAlgorithms.MLKEM512 => MLKemParameters.ml_kem_512,
        MlKemAlgorithms.MLKEM768 => MLKemParameters.ml_kem_768,
        MlKemAlgorithms.MLKEM1024 => MLKemParameters.ml_kem_1024,
        _ => throw new NotSupportedException($"ML-KEM algorithm '{algorithm}' is not supported.")
    };

    private static MLDsaAlgorithm GetNative(MlDsaAlgorithms algorithm) => algorithm switch {
        MlDsaAlgorithms.MLDSA44 => MLDsaAlgorithm.MLDsa44,
        MlDsaAlgorithms.MLDSA65 => MLDsaAlgorithm.MLDsa65,
        MlDsaAlgorithms.MLDSA87 => MLDsaAlgorithm.MLDsa87,
        _ => throw new NotSupportedException($"ML-DSA algorithm '{algorithm}' is not supported.")
    };

    private static MLDsaParameters GetBouncyCastle(MlDsaAlgorithms algorithm) => algorithm switch {
        MlDsaAlgorithms.MLDSA44 => MLDsaParameters.ml_dsa_44,
        MlDsaAlgorithms.MLDSA65 => MLDsaParameters.ml_dsa_65,
        MlDsaAlgorithms.MLDSA87 => MLDsaParameters.ml_dsa_87,
        _ => throw new NotSupportedException($"ML-DSA algorithm '{algorithm}' is not supported.")
    };
}
