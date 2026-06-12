using Mrbr.Service.KeyManager.Services;
using System.Buffers;
using System.Security.Cryptography;
namespace Mrbr.Service.EncryptionManager.Services.Encryption;

public class AesEncryptionService : IEncryptionService {
    public IKeyService KeyService => StaticKeyService;

    public AesEncryptionService(IKeyService keyService) {
        StaticKeyService ??= keyService;
    }

    private static IKeyService StaticKeyService { get; set; } = null!;

    private const char KeyPrefixDelimiter = ':';

    /// <summary>
    /// Decrypts classical encrypted text.
    /// </summary>
    public string Decrypt(string dataToDecrypt, IEncryptionOptions encryptionOptions) => DecryptText(dataToDecrypt, encryptionOptions);

    /// <summary>
    /// Encrypts plain text using classical encryption.
    /// </summary>
    public string Encrypt(string dataToEncrypt, IEncryptionOptions encryptionOptions) => EncryptText(dataToEncrypt, encryptionOptions);

    /// <summary>
    /// Encrypts text and returns the payload in <c>{keyResult}:{base64}</c> format.
    /// </summary>
    public static string EncryptText(string plainText, IEncryptionOptions encryptionOptions) {
        ArgumentNullException.ThrowIfNullOrEmpty(plainText, nameof(plainText));

        byte[] keyBytes = GetRequiredKeyService().GenerateKey256(out int keyResult);
        try {
            using var aes = Aes.Create();
            aes.Key = keyBytes;
            aes.GenerateIV();
            var iv = aes.IV;
            using var encryptor = aes.CreateEncryptor(aes.Key, iv);
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using (var sw = new StreamWriter(cs)) {
                sw.Write(plainText);
            }
            var encrypted = ms.ToArray();

            var resultLength = iv.Length + encrypted.Length;
            var pool = ArrayPool<byte>.Shared;
            byte[] result = pool.Rent(resultLength);
            try {
                iv.AsSpan().CopyTo(result.AsSpan(0, iv.Length));
                encrypted.AsSpan().CopyTo(result.AsSpan(iv.Length, encrypted.Length));
                return $"{keyResult}{KeyPrefixDelimiter}{Convert.ToBase64String(result.AsSpan(0, resultLength))}";
            }
            finally {
                pool.Return(result, clearArray: true);
            }
        }
        finally {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    /// <summary>
    /// Decrypts payloads in <c>{keyResult}:{base64}</c> format.
    /// </summary>
    public static string DecryptText(string cipherText, IEncryptionOptions encryptionOptions) {
        ArgumentNullException.ThrowIfNullOrEmpty(cipherText, nameof(cipherText));

        var parts = cipherText.Split(KeyPrefixDelimiter, 2);
        if (parts.Length != 2 || int.TryParse(parts[0], out int keyResult) == false) {
            throw new InvalidOperationException($"Invalid encrypted format: expected 'keyPrefix{KeyPrefixDelimiter}ciphertext'.");
        }

        var fullCipher = Convert.FromBase64String(parts[1]);
        byte[] keyBytes = GetRequiredKeyService().GetKey256(keyResult);
        try {
            using var aes = Aes.Create();
            aes.Key = keyBytes;

            var pool = ArrayPool<byte>.Shared;
            var ivLength = aes.BlockSize / 8;
            var cipherLength = fullCipher.Length - ivLength;
            if (cipherLength <= 0) {
                throw new InvalidOperationException("Encrypted payload does not contain a valid IV and ciphertext.");
            }

            byte[] iv = pool.Rent(ivLength);
            byte[] cipher = pool.Rent(cipherLength);
            try {
                fullCipher.AsSpan(0, ivLength).CopyTo(iv.AsSpan(0, ivLength));
                fullCipher.AsSpan(ivLength).CopyTo(cipher.AsSpan(0, cipherLength));
                aes.IV = iv.AsSpan(0, ivLength).ToArray();

                using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using var ms = new MemoryStream(cipher, 0, cipherLength);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                using var sr = new StreamReader(cs);
                return sr.ReadToEnd();
            }
            finally {
                pool.Return(iv, clearArray: true);
                pool.Return(cipher, clearArray: true);
            }
        }
        finally {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private static IKeyService GetRequiredKeyService() =>
        StaticKeyService ?? throw new InvalidOperationException("EncryptionService has not been initialised with an IKeyService instance.");
}
