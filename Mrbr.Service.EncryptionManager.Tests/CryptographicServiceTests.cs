using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.EncryptionManager.Extensions;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.KeyHandles;
using Mrbr.Service.KeyManager.Services;
using System.Security.Cryptography;
using System.Text;

namespace Mrbr.Service.EncryptionManager.Tests;

public partial class CryptographicServiceTests : IDisposable {
    private readonly KeyManagerTestEnvironment environment = new();
    public void Dispose() => environment.Dispose();
    [Fact]
    public void Encrypt_UsesExplicitKeySource() {
        var service = CreateService(0, 7);

        var encrypted = service.Encrypt(7, "source-specific encryption"u8.ToArray());

        Assert.Equal(7, KeyHandleCodec.GetKeySourceId(encrypted.KeyHandle));
        Assert.Equal(
            "source-specific encryption"u8.ToArray(),
            service.Decrypt(encrypted.KeyHandle, encrypted.Cipher));
    }

    [Fact]
    public void Encrypt_ThrowsWhenExplicitKeySourceIsMissing() {
        var service = CreateService();

        KeyNotFoundException exception = Assert.Throws<KeyNotFoundException>(
            () => service.Encrypt(7, "missing source"u8.ToArray()));

        Assert.Contains("7", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Hmac_UsesExplicitKeySource() {
        var service = CreateService(0, 7);
        byte[] data = "source-specific authentication"u8.ToArray();

        HmacResult result = service.Hmac(7, data);

        Assert.Equal(7, KeyHandleCodec.GetKeySourceId(result.KeyHandle));
        Assert.True(service.ValidateHmac(result.KeyHandle, data, result.Hmac));
    }

    [Theory]
    [InlineData(SymmetricEncryptionAlgorithms.AES128)]
    [InlineData(SymmetricEncryptionAlgorithms.AES192)]
    [InlineData(SymmetricEncryptionAlgorithms.AES256)]
    public void EncryptDecrypt_RoundTrips_ForSupportedAesAlgorithms(SymmetricEncryptionAlgorithms algorithm) {
        var service = CreateService();
        var options = new EncryptionOptions { Algorithm = algorithm };
        byte[] plainText = Encoding.UTF8.GetBytes("usage agnostic encryption artifact");

        var encrypted = service.Encrypt(0, plainText, options);
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

        int cipherLength = service.Encrypt(0, plainText, cipher, out ulong keyHandle);
        int plainTextLength = service.Decrypt(keyHandle, cipher, decrypted);

        Assert.Equal(cipher.Length, cipherLength);
        Assert.Equal(plainText.Length, plainTextLength);
        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void Encrypt_RejectsUnsupportedSymmetricAlgorithm() {
        var service = CreateService();
        var options = new EncryptionOptions { Algorithm = (SymmetricEncryptionAlgorithms)999 };

        Assert.Throws<NotSupportedException>(() => service.Encrypt(0, "unsupported aes"u8.ToArray(), options));
    }

    [Fact]
    public void Decrypt_RejectsUnsupportedSymmetricAlgorithm() {
        var service = CreateService();
        var encrypted = service.Encrypt(0, "unsupported aes decrypt"u8.ToArray());
        var options = new EncryptionOptions { Algorithm = (SymmetricEncryptionAlgorithms)999 };

        Assert.Throws<NotSupportedException>(() => service.Decrypt(encrypted.KeyHandle, encrypted.Cipher, options));
    }

    [Fact]
    public void Encrypt_RejectsTooSmallDestination() {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("small cipher destination");
        byte[] cipher = GC.AllocateUninitializedArray<byte>(CryptographicService.GetCipherLength(plainText.Length) - 1);

        var exception = Assert.Throws<ArgumentException>(() => service.Encrypt(0, plainText, cipher, out _));

        Assert.Equal("cipherDestination", exception.ParamName);
    }

    [Fact]
    public void Decrypt_RejectsTooSmallDestination() {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("small plain text destination");
        var encrypted = service.Encrypt(0, plainText);
        byte[] decrypted = GC.AllocateUninitializedArray<byte>(plainText.Length - 1);

        var exception = Assert.Throws<ArgumentException>(() => service.Decrypt(encrypted.KeyHandle, encrypted.Cipher, decrypted));

        Assert.Equal("plainTextDestination", exception.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]
    [InlineData(28)]
    public void Decrypt_RejectsTamperedCipherArtifact(int tamperIndex) {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("tamper detection requires non-empty cipher text");
        var encrypted = service.Encrypt(0, plainText);
        encrypted.Cipher[tamperIndex] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted.KeyHandle, encrypted.Cipher));
    }

    [Fact]
    public void Decrypt_RejectsTamperedKeyHandle() {
        var service = CreateService();
        byte[] plainText = Encoding.UTF8.GetBytes("key handle is authenticated associated data");
        var encrypted = service.Encrypt(0, plainText);
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

        var encrypted = service.Encrypt(0, plainText, encryptOptions);

        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(encrypted.KeyHandle, encrypted.Cipher, decryptOptions));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(27)]
    public void Decrypt_RejectsMalformedCipherLength(int cipherLength) {
        var service = CreateService();
        byte[] cipher = new byte[cipherLength];

        var exception = Assert.Throws<ArgumentException>(() => service.Decrypt(0, cipher));

        Assert.Equal("cipherLength", exception.ParamName);
    }

    [Fact]
    public void TextHelpers_RoundTripAsKeyHandleBase64Payload() {
        var service = CreateService();
        const string plainText = "UTF-8 text helper";

        string encrypted = service.EncryptText(0, plainText);
        string decrypted = service.DecryptText(encrypted);

        Assert.Contains(':', encrypted);
        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void TextHelpers_RejectInvalidTextInputs() {
        var service = CreateService();
        string? nullText = null;

        Assert.Throws<ArgumentNullException>(() => service.EncryptText(0, nullText!));
        Assert.Throws<ArgumentNullException>(() => service.DecryptText(nullText!));
        Assert.Throws<ArgumentException>(() => service.DecryptText(""));
        Assert.Throws<ArgumentException>(() => service.DecryptText("   "));
    }

    [Fact]
    public void ArtifactSerializer_RoundTripsSupportedFormats() {
        var service = CreateService();
        var encrypted = service.Encrypt(0, Encoding.UTF8.GetBytes("serializer formats"));

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
    public void ArtifactSerializer_RejectsInvalidBase64AndHexArtifacts() {
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromBase64("not-base64"));
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromHex("GG"));
        Assert.Throws<ArgumentNullException>(() => CryptographicArtifactSerializer.FromBase64(null!));
        Assert.Throws<ArgumentNullException>(() => CryptographicArtifactSerializer.FromHex(null!));
    }

    [Fact]
    public void EncryptionResultSerializer_RoundTripsTypedFormats() {
        var service = CreateService();
        var encrypted = service.Encrypt(0, Encoding.UTF8.GetBytes("typed encryption serializer formats"));

        byte[] rawCipher = encrypted.ToCipherBytes();
        string base64 = encrypted.ToCipherBase64();
        string hex = encrypted.ToCipherHex();
        byte[] keyedCipherBytes = encrypted.ToKeyHandleCipherBytes();
        string keyedBase64 = encrypted.ToKeyHandleCipherBase64();
        string keyedHex = encrypted.ToKeyHandleCipherHex();
        var keyedArtifact = encrypted.ToKeyedArtifact();

        Assert.NotSame(encrypted.Cipher, rawCipher);
        Assert.Equal(encrypted.Cipher, rawCipher);
        Assert.Equal(encrypted.Cipher, CryptographicArtifactSerializer.FromBase64(base64));
        Assert.Equal(encrypted.Cipher, CryptographicArtifactSerializer.FromHex(hex));
        Assert.Equal(encrypted.Cipher, encrypted.ToArtifactBytes(CryptographicArtifactFormat.Raw));
        Assert.Equal(base64, encrypted.ToArtifactText(CryptographicArtifactFormat.Base64));
        Assert.Equal(hex, encrypted.ToArtifactText(CryptographicArtifactFormat.Hex));

        var parsedKeyedBytes = CryptographicArtifactSerializer.FromKeyHandleArtifactBytes(keyedCipherBytes);
        var parsedKeyedBase64 = CryptographicArtifactSerializer.FromKeyHandleBase64(keyedBase64);
        var parsedKeyedHex = CryptographicArtifactSerializer.FromKeyHandleHex(keyedHex);

        Assert.Equal(encrypted.KeyHandle, keyedArtifact.KeyHandle);
        Assert.Equal(encrypted.Cipher, keyedArtifact.Artifact);
        Assert.NotSame(encrypted.Cipher, keyedArtifact.Artifact);
        Assert.Equal(parsedKeyedBytes.Artifact, encrypted.Cipher);
        Assert.Equal(parsedKeyedBase64.Artifact, encrypted.Cipher);
        Assert.Equal(parsedKeyedHex.Artifact, encrypted.Cipher);
        Assert.Equal(keyedCipherBytes, encrypted.ToArtifactBytes(CryptographicArtifactFormat.KeyHandleRaw));
        Assert.Equal(keyedBase64, encrypted.ToArtifactText(CryptographicArtifactFormat.KeyHandleBase64));
        Assert.Equal(keyedHex, encrypted.ToArtifactText(CryptographicArtifactFormat.KeyHandleHex));
        Assert.Throws<NotSupportedException>(() => encrypted.ToArtifactBytes(CryptographicArtifactFormat.Base64));
        Assert.Throws<NotSupportedException>(() => encrypted.ToArtifactText(CryptographicArtifactFormat.Raw));
    }

    [Fact]
    public void ArtifactSerializer_RejectsInvalidKeyedTextArtifacts() {
        Assert.Throws<ArgumentNullException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64(null!));
        Assert.Throws<ArgumentException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64(""));
        Assert.Throws<ArgumentException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64("   "));

        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64("123"));
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64(":AA=="));
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64("abc:AA=="));
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64("123:"));
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleBase64("123:not-base64"));
        Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleHex("123:GG"));
    }

    [Fact]
    public void ArtifactSerializer_RejectsInvalidKeyedRawArtifacts() {
        byte[][] invalidArtifacts = [
            [],
            Encoding.ASCII.GetBytes("123"),
            Encoding.ASCII.GetBytes(":artifact"),
            Encoding.ASCII.GetBytes("abc:artifact"),
            Encoding.ASCII.GetBytes("123:")
        ];

        foreach (byte[] artifact in invalidArtifacts) {
            Assert.Throws<FormatException>(() => CryptographicArtifactSerializer.FromKeyHandleArtifactBytes(artifact));
        }
    }

    [Fact]
    public void AddEncryptionManager_ResolvesCryptographicService_WhenKeyServiceIsRegistered() {
        var services = new ServiceCollection();
        services.AddSingleton<IKeyService>(CreateKeyService());
        services.AddEncryptionManager();

        using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<ICryptographicService>();
        var encrypted = service.Encrypt(0, Encoding.UTF8.GetBytes("resolved from DI"));
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
    public void Hash_RejectsTooSmallDestination() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("small hash destination");
        byte[] destination = GC.AllocateUninitializedArray<byte>(CryptographicService.GetHashLength(HashingAlgorithms.SHA256) - 1);

        var exception = Assert.Throws<ArgumentException>(() => service.Hash(data, destination));

        Assert.Equal("hashDestination", exception.ParamName);
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
    public void ValidateHash_ReturnsFalse_ForWrongLengthHash() {
        var service = CreateService();

        Assert.False(service.ValidateHash("wrong length hash"u8.ToArray(), []));
    }

    [Fact]
    public void Hash_RejectsUnsupportedDeclaredAlgorithm() {
        var service = CreateService();

        Assert.Throws<NotSupportedException>(() =>
            service.Hash(Encoding.UTF8.GetBytes("legacy"), new HashOptions { Algorithm = HashingAlgorithms.MD5 }));
    }

    [Fact]
    public void Hash_RejectsUnsupportedEnumValue() {
        var service = CreateService();

        Assert.Throws<NotSupportedException>(() =>
            service.Hash("invalid enum hash"u8.ToArray(), new HashOptions { Algorithm = (HashingAlgorithms)999 }));
    }

    [Theory]
    [InlineData(HmacAlgorithms.HMACSHA256)]
    [InlineData(HmacAlgorithms.HMACSHA384)]
    [InlineData(HmacAlgorithms.HMACSHA512)]
    public void Hmac_ReturnsReplayableHmac_ForSupportedAlgorithms(HmacAlgorithms algorithm) {
        var service = CreateService();
        var options = new HmacOptions { Algorithm = algorithm };
        byte[] data = Encoding.UTF8.GetBytes("authenticated payload");

        var result = service.Hmac(0, data, options);

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

        var result = service.Hmac(0, data, options);

        Assert.True(service.ValidateHmac(result.KeyHandle, data, result.Hmac, options));
    }

    [Fact]
    public void Hmac_SpanOverload_WritesExpectedLength() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("span hmac");
        var options = new HmacOptions { Algorithm = HmacAlgorithms.HMACSHA512 };
        byte[] destination = GC.AllocateUninitializedArray<byte>(CryptographicService.GetHmacLength(options.Algorithm));

        int bytesWritten = service.Hmac(0, data, destination, out ulong keyHandle, options);

        Assert.Equal(destination.Length, bytesWritten);
        Assert.True(service.ValidateHmac(keyHandle, data, destination, options));
    }

    [Theory]
    [InlineData(HmacAlgorithms.HMACSHA256)]
    [InlineData(HmacAlgorithms.HMACSHA384)]
    [InlineData(HmacAlgorithms.HMACSHA512)]
    public void HmacWithKeyHandle_IsDeterministicAndReplaysProvisionedKey(HmacAlgorithms algorithm) {
        var service = CreateService();
        var options = new HmacOptions { Algorithm = algorithm };
        byte[] data = Encoding.UTF8.GetBytes("deterministic searchable value");
        HmacResult provisioned = service.Hmac(0, data, options);

        byte[] first = service.HmacWithKeyHandle(provisioned.KeyHandle, data, options);
        byte[] second = service.HmacWithKeyHandle(provisioned.KeyHandle, data, options);

        Assert.Equal(provisioned.Hmac, first);
        Assert.Equal(first, second);
        Assert.False(first.SequenceEqual(service.HmacWithKeyHandle(
            provisioned.KeyHandle,
            "different searchable value"u8.ToArray(),
            options)));
    }

    [Fact]
    public void HmacWithKeyHandle_SpanOverload_WritesExpectedLength() {
        var service = CreateService();
        HmacResult provisioned = service.Hmac(0, "provision key"u8.ToArray());
        byte[] destination = new byte[CryptographicService.GetHmacLength(HmacAlgorithms.HMACSHA256)];

        int bytesWritten = service.HmacWithKeyHandle(
            provisioned.KeyHandle,
            "search value"u8.ToArray(),
            destination);

        Assert.Equal(destination.Length, bytesWritten);
        Assert.True(service.ValidateHmac(
            provisioned.KeyHandle,
            "search value"u8.ToArray(),
            destination));
    }

    [Fact]
    public void HmacWithKeyHandle_RejectsTooSmallDestination() {
        var service = CreateService();
        HmacResult provisioned = service.Hmac(0, "provision key"u8.ToArray());
        byte[] destination = new byte[CryptographicService.GetHmacLength(HmacAlgorithms.HMACSHA256) - 1];

        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            service.HmacWithKeyHandle(
                provisioned.KeyHandle,
                "search value"u8.ToArray(),
                destination));

        Assert.Equal("hmacDestination", exception.ParamName);
    }

    [Fact]
    public void Hmac_RejectsTooSmallDestination() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("small hmac destination");
        byte[] destination = GC.AllocateUninitializedArray<byte>(CryptographicService.GetHmacLength(HmacAlgorithms.HMACSHA256) - 1);

        var exception = Assert.Throws<ArgumentException>(() => service.Hmac(0, data, destination, out _));

        Assert.Equal("hmacDestination", exception.ParamName);
    }

    [Fact]
    public void ValidateHmac_ReturnsFalse_ForTamperedInputs() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("hmac tamper");
        var result = service.Hmac(0, data);
        byte[] tamperedData = Encoding.UTF8.GetBytes("hmac tamper!");
        byte[] tamperedHmac = result.Hmac.ToArray();
        tamperedHmac[0] ^= 0x01;
        ulong tamperedKeyHandle = result.KeyHandle ^ (1UL << 16);

        Assert.False(service.ValidateHmac(result.KeyHandle, tamperedData, result.Hmac));
        Assert.False(service.ValidateHmac(result.KeyHandle, data, tamperedHmac));
        Assert.False(service.ValidateHmac(tamperedKeyHandle, data, result.Hmac));
    }

    [Fact]
    public void ValidateHmac_ReturnsFalse_ForWrongLengthHmac() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("wrong length hmac");
        var result = service.Hmac(0, data);

        Assert.False(service.ValidateHmac(result.KeyHandle, data, []));
    }

    [Fact]
    public void Hmac_RejectsUnsupportedAlgorithm() {
        var service = CreateService();

        Assert.Throws<NotSupportedException>(() =>
            service.Hmac(0, "invalid hmac algorithm"u8.ToArray(), new HmacOptions { Algorithm = (HmacAlgorithms)999 }));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(127)]
    [InlineData(129)]
    [InlineData(512)]
    public void Hmac_RejectsUnsupportedKeySize(int keySizeInBits) {
        var service = CreateService();
        var options = new HmacOptions { KeySizeInBits = keySizeInBits };

        Assert.Throws<NotSupportedException>(() => service.Hmac(0, "invalid hmac key size"u8.ToArray(), options));
    }

    [Fact]
    public void ValidateHmac_RejectsUnsupportedKeySize() {
        var service = CreateService();
        byte[] data = Encoding.UTF8.GetBytes("invalid validation key size");
        var result = service.Hmac(0, data);
        var options = new HmacOptions { KeySizeInBits = 512 };

        Assert.Throws<NotSupportedException>(() => service.ValidateHmac(result.KeyHandle, data, result.Hmac, options));
    }

    [Fact]
    public void HmacSerializer_RoundTripsSupportedKeyedFormats() {
        var service = CreateService();
        var hmac = service.Hmac(0, Encoding.UTF8.GetBytes("hmac serializer formats"));

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

    [Fact]
    public void HmacResultSerializer_RoundTripsTypedFormats() {
        var service = CreateService();
        var hmac = service.Hmac(0, Encoding.UTF8.GetBytes("typed hmac serializer formats"));

        byte[] rawHmac = hmac.ToHmacBytes();
        string base64 = hmac.ToHmacBase64();
        string hex = hmac.ToHmacHex();
        byte[] keyedHmacBytes = hmac.ToKeyHandleHmacBytes();
        string keyedBase64 = hmac.ToKeyHandleHmacBase64();
        string keyedHex = hmac.ToKeyHandleHmacHex();
        var keyedArtifact = hmac.ToKeyedArtifact();

        Assert.NotSame(hmac.Hmac, rawHmac);
        Assert.Equal(hmac.Hmac, rawHmac);
        Assert.Equal(hmac.Hmac, CryptographicArtifactSerializer.FromBase64(base64));
        Assert.Equal(hmac.Hmac, CryptographicArtifactSerializer.FromHex(hex));
        Assert.Equal(hmac.Hmac, hmac.ToArtifactBytes(CryptographicArtifactFormat.Raw));
        Assert.Equal(base64, hmac.ToArtifactText(CryptographicArtifactFormat.Base64));
        Assert.Equal(hex, hmac.ToArtifactText(CryptographicArtifactFormat.Hex));

        var parsedKeyedBytes = CryptographicArtifactSerializer.FromKeyHandleArtifactBytes(keyedHmacBytes);
        var parsedKeyedBase64 = CryptographicArtifactSerializer.FromKeyHandleBase64(keyedBase64);
        var parsedKeyedHex = CryptographicArtifactSerializer.FromKeyHandleHex(keyedHex);

        Assert.Equal(hmac.KeyHandle, keyedArtifact.KeyHandle);
        Assert.Equal(hmac.Hmac, keyedArtifact.Artifact);
        Assert.NotSame(hmac.Hmac, keyedArtifact.Artifact);
        Assert.Equal(parsedKeyedBytes.Artifact, hmac.Hmac);
        Assert.Equal(parsedKeyedBase64.Artifact, hmac.Hmac);
        Assert.Equal(parsedKeyedHex.Artifact, hmac.Hmac);
        Assert.Equal(keyedHmacBytes, hmac.ToArtifactBytes(CryptographicArtifactFormat.KeyHandleRaw));
        Assert.Equal(keyedBase64, hmac.ToArtifactText(CryptographicArtifactFormat.KeyHandleBase64));
        Assert.Equal(keyedHex, hmac.ToArtifactText(CryptographicArtifactFormat.KeyHandleHex));
        Assert.Throws<NotSupportedException>(() => hmac.ToArtifactBytes(CryptographicArtifactFormat.Base64));
        Assert.Throws<NotSupportedException>(() => hmac.ToArtifactText(CryptographicArtifactFormat.Raw));
    }

    private ICryptographicService CreateService(params byte[] keySourceIds) =>
        new CryptographicService(CreateKeyService(keySourceIds));

    private IKeyService CreateKeyService(params byte[] keySourceIds) =>
        environment.Create(keySourceIds.Length == 0 ? [0] : keySourceIds);

    private static byte[] ComputeExpectedHash(HashingAlgorithms algorithm, byte[] data) =>
        algorithm switch {
            HashingAlgorithms.SHA256 => SHA256.HashData(data),
            HashingAlgorithms.SHA384 => SHA384.HashData(data),
            HashingAlgorithms.SHA512 => SHA512.HashData(data),
            _ => throw new NotSupportedException()
        };
}
