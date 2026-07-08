using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.Services;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Mrbr.Service.EncryptionManager.Tests;

public class CryptographicServiceTests {
    [Theory]
    [InlineData(SymmetricEncryptionAlgorithms.AES128)]
    [InlineData(SymmetricEncryptionAlgorithms.AES192)]
    [InlineData(SymmetricEncryptionAlgorithms.AES256)]
    public void EncryptDecrypt_RoundTrips_ForSupportedAesAlgorithms(SymmetricEncryptionAlgorithms algorithm) {
        var service = CreateService();
        var options = new EncryptionOptions { Algorithm = algorithm };
        byte[] plainText = Encoding.UTF8.GetBytes("usage agnostic encryption artifact");

        var encrypted = service.Encrypt(plainText, options);
        byte[] decrypted = service.Decrypt(encrypted.KeyHandle, encrypted.Cipher, options);

        Assert.Equal(CryptographicService.GetCipherLength(plainText.Length), encrypted.Cipher.Length);
        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_SpanOverloads_RoundTripWithoutResultAllocation() {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("span based encryption");
        byte[] cipher = GC.AllocateUninitializedArray<byte>(CryptographicService.GetCipherLength(plainText.Length));
        byte[] decrypted = GC.AllocateUninitializedArray<byte>(plainText.Length);

        int cipherLength = service.Encrypt(plainText, cipher, out ulong keyHandle);
        int plainTextLength = service.Decrypt(keyHandle, cipher, decrypted);

        Assert.Equal(cipher.Length, cipherLength);
        Assert.Equal(plainText.Length, plainTextLength);
        Assert.Equal(plainText, decrypted);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]
    [InlineData(28)]
    public void Decrypt_RejectsTamperedCipherArtifact(int tamperIndex) {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("tamper detection requires non-empty cipher text");
        var encrypted = service.Encrypt(plainText);
        encrypted.Cipher[tamperIndex] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted.KeyHandle, encrypted.Cipher));
    }

    [Fact]
    public void Decrypt_RejectsTamperedKeyHandle() {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("key handle is authenticated associated data");
        var encrypted = service.Encrypt(plainText);
        ulong tamperedKeyHandle = encrypted.KeyHandle ^ (1UL << 16);

        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(tamperedKeyHandle, encrypted.Cipher));
    }

    [Fact]
    public void Decrypt_RejectsTamperedAssociatedData() {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("associated data matters");
        var encryptOptions = new EncryptionOptions {
            AssociatedData = Encoding.UTF8.GetBytes("first-context")
        };
        var decryptOptions = new EncryptionOptions {
            AssociatedData = Encoding.UTF8.GetBytes("second-context")
        };

        var encrypted = service.Encrypt(plainText, encryptOptions);

        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted.KeyHandle, encrypted.Cipher, decryptOptions));
    }

    [Fact]
    public void TextHelpers_RoundTripAsKeyHandleBase64Payload() {
        var service = CreateService();
        const string plainText = "UTF-8 text helper";

        string encrypted = service.EncryptText(plainText);
        string decrypted = service.DecryptText(encrypted);

        Assert.Contains(':', encrypted);
        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void ArtifactSerializer_RoundTripsSupportedFormats() {
        var service = CreateService();
        var encrypted = service.Encrypt(Encoding.UTF8.GetBytes("serializer formats"));

        byte[] rawArtifact = encrypted.Cipher;
        string base64 = CryptographicArtifactSerializer.ToBase64(rawArtifact);
        string hex = CryptographicArtifactSerializer.ToHex(rawArtifact);
        string keyedBase64 = CryptographicArtifactSerializer.ToKeyHandleBase64(encrypted.KeyHandle, rawArtifact);
        string keyedHex = CryptographicArtifactSerializer.ToKeyHandleHex(encrypted.KeyHandle, rawArtifact);
        byte[] keyedArtifactBytes = CryptographicArtifactSerializer.ToKeyHandleArtifactBytes(encrypted.KeyHandle, rawArtifact);

        Assert.Equal(rawArtifact, CryptographicArtifactSerializer.FromBase64(base64));
        Assert.Equal(rawArtifact, CryptographicArtifactSerializer.FromHex(hex));

        var parsedKeyedBase64 = CryptographicArtifactSerializer.FromKeyHandleBase64(keyedBase64);
        var parsedKeyedHex = CryptographicArtifactSerializer.FromKeyHandleHex(keyedHex);
        var parsedKeyedBytes = CryptographicArtifactSerializer.FromKeyHandleArtifactBytes(keyedArtifactBytes);

        Assert.Equal(encrypted.KeyHandle, parsedKeyedBase64.KeyHandle);
        Assert.Equal(rawArtifact, parsedKeyedBase64.Artifact);
        Assert.Equal(encrypted.KeyHandle, parsedKeyedHex.KeyHandle);
        Assert.Equal(rawArtifact, parsedKeyedHex.Artifact);
        Assert.Equal(encrypted.KeyHandle, parsedKeyedBytes.KeyHandle);
        Assert.Equal(rawArtifact, parsedKeyedBytes.Artifact);
    }

    [Fact]
    public void AddEncryptionManager_ResolvesCryptographicService_WhenKeyServiceIsRegistered() {
        var services = new ServiceCollection();
        services.AddSingleton<IKeyService>(CreateKeyService());
        services.AddEncryptionManager();

        using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<ICryptographicService>();
        var encrypted = service.Encrypt(Encoding.UTF8.GetBytes("resolved from DI"));
        byte[] decrypted = service.Decrypt(encrypted.KeyHandle, encrypted.Cipher);

        Assert.Equal("resolved from DI", Encoding.UTF8.GetString(decrypted));
    }

    [Fact]
    public void AddEncryptionManager_FailsClearly_WhenKeyServiceIsMissing() {
        var services = new ServiceCollection();
        services.AddEncryptionManager();

        using var provider = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<ICryptographicService>());
    }

    [Theory]
    [InlineData(HashingAlgorithms.SHA256)]
    [InlineData(HashingAlgorithms.SHA384)]
    [InlineData(HashingAlgorithms.SHA512)]
    public void Hash_RoundTripsSupportedAlgorithms(HashingAlgorithms algorithm) {
        var service = CreateService();
        var options = new HashOptions { Algorithm = algorithm };
        byte[] data = Encoding.UTF8.GetBytes("hash me");

        var result = service.Hash(data, options);
        byte[] expected = ComputeExpectedHash(algorithm, data);

        Assert.Equal(expected, result.Hash);
        Assert.True(service.ValidateHash(data, result.Hash, options));
    }

    [Fact]
    public void Hash_SpanOverload_WritesExpectedLength() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("span hash");
        byte[] destination = GC.AllocateUninitializedArray<byte>(CryptographicService.GetHashLength(HashingAlgorithms.SHA384));

        int bytesWritten = service.Hash(data, destination, new HashOptions { Algorithm = HashingAlgorithms.SHA384 });

        Assert.Equal(destination.Length, bytesWritten);
        Assert.Equal(SHA384.HashData(data), destination);
    }

    [Fact]
    public void ValidateHash_ReturnsFalse_ForTamperedHash() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("hash tamper");
        var result = service.Hash(data);
        result.Hash[0] ^= 0x01;

        Assert.False(service.ValidateHash(data, result.Hash));
    }

    [Fact]
    public void Hash_RejectsUnsupportedDeclaredAlgorithm() {
        var service = CreateService();

        Assert.Throws<NotSupportedException>(() =>
            service.Hash(Encoding.UTF8.GetBytes("legacy"), new HashOptions { Algorithm = HashingAlgorithms.MD5 }));
    }

    [Theory]
    [InlineData(HmacAlgorithms.HMACSHA256)]
    [InlineData(HmacAlgorithms.HMACSHA384)]
    [InlineData(HmacAlgorithms.HMACSHA512)]
    public void Hmac_ReturnsReplayableHmac_ForSupportedAlgorithms(HmacAlgorithms algorithm) {
        var service = CreateService();
        var options = new HmacOptions { Algorithm = algorithm };
        byte[] data = Encoding.UTF8.GetBytes("authenticated payload");

        var result = service.Hmac(data, options);

        Assert.Equal(CryptographicService.GetHmacLength(algorithm), result.Hmac.Length);
        Assert.True(service.ValidateHmac(result.KeyHandle, data, result.Hmac, options));
    }

    [Theory]
    [InlineData(128)]
    [InlineData(192)]
    [InlineData(256)]
    public void Hmac_ReturnsReplayableHmac_ForSupportedKeySizes(int keySizeInBits) {
        var service = CreateService();
        var options = new HmacOptions { KeySizeInBits = keySizeInBits };
        byte[] data = Encoding.UTF8.GetBytes("authenticated with selectable key material");

        var result = service.Hmac(data, options);

        Assert.True(service.ValidateHmac(result.KeyHandle, data, result.Hmac, options));
    }

    [Fact]
    public void Hmac_SpanOverload_WritesExpectedLength() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("span hmac");
        var options = new HmacOptions { Algorithm = HmacAlgorithms.HMACSHA512 };
        byte[] destination = GC.AllocateUninitializedArray<byte>(CryptographicService.GetHmacLength(options.Algorithm));

        int bytesWritten = service.Hmac(data, destination, out ulong keyHandle, options);

        Assert.Equal(destination.Length, bytesWritten);
        Assert.True(service.ValidateHmac(keyHandle, data, destination, options));
    }

    [Fact]
    public void ValidateHmac_ReturnsFalse_ForTamperedInputs() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("hmac tamper");
        var result = service.Hmac(data);
        byte[] tamperedData = Encoding.UTF8.GetBytes("hmac tamper!");
        byte[] tamperedHmac = result.Hmac.ToArray();
        tamperedHmac[0] ^= 0x01;
        ulong tamperedKeyHandle = result.KeyHandle ^ (1UL << 16);

        Assert.False(service.ValidateHmac(result.KeyHandle, tamperedData, result.Hmac));
        Assert.False(service.ValidateHmac(result.KeyHandle, data, tamperedHmac));
        Assert.False(service.ValidateHmac(tamperedKeyHandle, data, result.Hmac));
    }

    [Fact]
    public void HmacSerializer_RoundTripsSupportedKeyedFormats() {
        var service = CreateService();
        var hmac = service.Hmac(Encoding.UTF8.GetBytes("hmac serializer formats"));

        string keyedBase64 = CryptographicArtifactSerializer.ToKeyHandleBase64(hmac.KeyHandle, hmac.Hmac);
        string keyedHex = CryptographicArtifactSerializer.ToKeyHandleHex(hmac.KeyHandle, hmac.Hmac);
        byte[] keyedArtifactBytes = CryptographicArtifactSerializer.ToKeyHandleArtifactBytes(hmac.KeyHandle, hmac.Hmac);

        var parsedKeyedBase64 = CryptographicArtifactSerializer.FromKeyHandleBase64(keyedBase64);
        var parsedKeyedHex = CryptographicArtifactSerializer.FromKeyHandleHex(keyedHex);
        var parsedKeyedBytes = CryptographicArtifactSerializer.FromKeyHandleArtifactBytes(keyedArtifactBytes);

        Assert.Equal(hmac.KeyHandle, parsedKeyedBase64.KeyHandle);
        Assert.Equal(hmac.Hmac, parsedKeyedBase64.Artifact);
        Assert.Equal(hmac.KeyHandle, parsedKeyedHex.KeyHandle);
        Assert.Equal(hmac.Hmac, parsedKeyedHex.Artifact);
        Assert.Equal(hmac.KeyHandle, parsedKeyedBytes.KeyHandle);
        Assert.Equal(hmac.Hmac, parsedKeyedBytes.Artifact);
    }

    private static ICryptographicService CreateService() => new CryptographicService(CreateKeyService());

    private static IKeyService CreateKeyService() {
        ResetKeyServiceOptionsState();
        var config = new KeyServiceConfig {
            new() {
                KeySourceId = 0,
                Value = BuildAsciiSourceText(4096),
                KeyHandleMask = "565342976",
                Type = KeyType.Block,
                BlockSettings = new KeyBlockSettings {
                    MinLength = 64,
                    MaxLength = 128
                }
            }
        };

        return new KeyService(new KeyServiceOptions(Options.Create(config)));
    }

    private static void ResetKeyServiceOptionsState() {
        var type = typeof(KeyServiceOptions);

        type.GetField("_keys", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyMemory", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyBytes", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keySourceIds", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, null);
        type.GetField("_keyCount", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, 0);
        type.GetField("_initialised", BindingFlags.NonPublic | BindingFlags.Static)?.SetValue(null, false);
    }

    private static string BuildAsciiSourceText(int length) {
        return string.Create(length, length, static (span, targetLength) => {
            for (int i = 0; i < targetLength; i++) {
                span[i] = (char)('!' + (i % 90));
            }
        });
    }

    private static byte[] ComputeExpectedHash(HashingAlgorithms algorithm, byte[] data) =>
        algorithm switch {
            HashingAlgorithms.SHA256 => SHA256.HashData(data),
            HashingAlgorithms.SHA384 => SHA384.HashData(data),
            HashingAlgorithms.SHA512 => SHA512.HashData(data),
            _ => throw new NotSupportedException()
        };
}
