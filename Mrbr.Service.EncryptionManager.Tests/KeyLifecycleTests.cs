using Mrbr.Service.EncryptionManager.Enums.Algorithms;
using Mrbr.Service.EncryptionManager.Services;
using Mrbr.Service.KeyManager.Configuration;
using Mrbr.Service.KeyManager.KeyHandles;
using System.Security.Cryptography;

namespace Mrbr.Service.EncryptionManager.Tests;

public partial class CryptographicServiceTests {
    [Theory]
    [InlineData(KeyType.Block)]
    [InlineData(KeyType.Matrix)]
    public void Lifecycle_PreservesReplayAndBlocksGeneration(KeyType type) {
        using var keys = environment.Create([0], type);
        var crypto = new CryptographicService(keys);
        byte[] data = "existing data and future lookup"u8.ToArray();
        var encrypted = crypto.Encrypt(0, data);
        string text = crypto.EncryptText(0, "existing text");
        var hmac = crypto.Hmac(0, data);
        var deterministic = crypto.HmacWithKeyHandle(hmac.KeyHandle, data);
        var kemOptions = new PostQuantumEncryptionOptions(MlKemAlgorithms.MLKEM512);
        var signatureOptions = new PostQuantumSignatureOptions(MlDsaAlgorithms.MLDSA44);
        var pqc = crypto.EncryptPostQuantum(0, data, kemOptions);
        var signed = crypto.SignPostQuantum(0, data, signatureOptions);
        foreach (var state in new[] { KeySourceState.Disabled, KeySourceState.Enabled, KeySourceState.Retired }) {
            environment.SetState(state);
            Assert.Equal(data, crypto.Decrypt(encrypted.KeyHandle, encrypted.Cipher));
            byte[] plainDestination = new byte[data.Length];
            Assert.Equal(data.Length, crypto.Decrypt(encrypted.KeyHandle, encrypted.Cipher, plainDestination));
            Assert.Equal(data, plainDestination);
            Assert.Equal("existing text", crypto.DecryptText(text));
            Assert.True(crypto.ValidateHmac(hmac.KeyHandle, data, hmac.Hmac));
            Assert.Equal(deterministic, crypto.HmacWithKeyHandle(hmac.KeyHandle, data));
            var replayDestination = new byte[deterministic.Length];
            crypto.HmacWithKeyHandle(hmac.KeyHandle, data, replayDestination);
            Assert.Equal(deterministic, replayDestination);
            // Computing a token for a new lookup input still replays the same existing key.
            Assert.Equal(crypto.HmacWithKeyHandle(hmac.KeyHandle, "another lookup"u8),
                crypto.HmacWithKeyHandle(hmac.KeyHandle, "another lookup"u8));
            Assert.Equal(data, crypto.DecryptPostQuantum(pqc.KeyHandle, pqc.Cipher, kemOptions));
            Assert.True(crypto.TryDecryptPostQuantum(pqc.KeyHandle, pqc.Cipher, kemOptions).IsSuccess);
            Assert.True(crypto.VerifyPostQuantum(signed.KeyHandle, data, signed.Signature, signatureOptions));
            Assert.False(crypto.VerifyPostQuantum(signed.KeyHandle, "tampered"u8, signed.Signature, signatureOptions));
            Assert.False(crypto.ValidateHmac(hmac.KeyHandle, "tampered"u8, hmac.Hmac));
            if (state == KeySourceState.Enabled) {
                crypto.Encrypt(0, data); crypto.Hmac(0, data);
                crypto.EncryptPostQuantum(0, data, kemOptions); crypto.SignPostQuantum(0, data, signatureOptions);
            } else {
                Assert.Throws<InvalidOperationException>(() => crypto.Encrypt(0, data));
                Assert.Throws<InvalidOperationException>(() => crypto.EncryptText(0, "new"));
                Assert.Throws<InvalidOperationException>(() => crypto.Encrypt(0, data, new byte[data.Length + 28], out _));
                Assert.Throws<InvalidOperationException>(() => crypto.Hmac(0, data));
                Assert.Throws<InvalidOperationException>(() => crypto.Hmac(0, data, new byte[32], out _));
                Assert.Throws<InvalidOperationException>(() => crypto.EncryptPostQuantum(0, data, kemOptions));
                Assert.Throws<InvalidOperationException>(() => crypto.SignPostQuantum(0, data, signatureOptions));
            }
        }
        Assert.Throws<KeyConfigurationException>(() => environment.SetState(KeySourceState.Enabled));
        Assert.Equal(KeySourceState.Retired, keys.GetSourceState(0));
    }

    [Fact]
    public void RotationUsesExplicitReplacementAndRejectedUpdatePreservesData() {
        using var keys = environment.Create([0]);
        var crypto = new CryptographicService(keys);
        var old = crypto.Encrypt(0, "old data"u8);
        environment.Config.Add(KeyServiceEntry.FromBytes(7, RandomNumberGenerator.GetBytes(4096)));
        environment.SetState(KeySourceState.Retired);
        var replacement = crypto.Encrypt(7, "new data"u8);
        Assert.Equal(7, KeyHandleCodec.GetKeySourceId(replacement.KeyHandle));
        Assert.Equal("old data"u8.ToArray(), crypto.Decrypt(old.KeyHandle, old.Cipher));
        environment.Config[1].Value = KeyServiceEntry.FromBytes(7, RandomNumberGenerator.GetBytes(4096)).Value;
        var failure = Assert.Throws<KeyConfigurationException>(() => environment.Options.ApplyConfiguration(environment.Config));
        Assert.DoesNotContain(environment.Config[1].Value, failure.ToString());
        Assert.Equal("new data"u8.ToArray(), crypto.Decrypt(replacement.KeyHandle, replacement.Cipher));
        Assert.True(KeyConfigurationAudit.TryDequeue(out _));
    }
}
