namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Provides usage-agnostic cryptographic operations backed by KeyManager-supplied key material.
/// </summary>
public interface ICryptographicService {
    /// <summary>
    /// Encrypts bytes with AES-GCM and returns the replay key handle with the cipher artifact.
    /// </summary>
    /// <param name="dataToEncrypt">Bytes to encrypt.</param>
    /// <param name="encryptionOptions">Optional AES-GCM encryption settings.</param>
    /// <returns>The key handle and cipher artifact.</returns>
    /// <remarks>The cipher artifact layout is nonce[12] + tag[16] + ciphertext.</remarks>
    EncryptionResult Encrypt(ReadOnlySpan<byte> dataToEncrypt, EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Encrypts bytes with AES-GCM into a caller-provided destination buffer.
    /// </summary>
    /// <param name="dataToEncrypt">Bytes to encrypt.</param>
    /// <param name="cipherDestination">Destination for nonce[12] + tag[16] + ciphertext.</param>
    /// <param name="keyHandle">Receives the KeyManager handle required for decryption.</param>
    /// <param name="encryptionOptions">Optional AES-GCM encryption settings.</param>
    /// <returns>The number of bytes written to <paramref name="cipherDestination" />.</returns>
    int Encrypt(
        ReadOnlySpan<byte> dataToEncrypt,
        Span<byte> cipherDestination,
        out ulong keyHandle,
        EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Decrypts an AES-GCM cipher artifact with replayed KeyManager key material.
    /// </summary>
    /// <param name="keyHandle">The key handle returned by encryption.</param>
    /// <param name="cipher">The nonce[12] + tag[16] + ciphertext artifact.</param>
    /// <param name="encryptionOptions">Optional AES-GCM decryption settings.</param>
    /// <returns>The decrypted bytes.</returns>
    byte[] Decrypt(ulong keyHandle, ReadOnlySpan<byte> cipher, EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Decrypts an AES-GCM cipher artifact into a caller-provided destination buffer.
    /// </summary>
    /// <param name="keyHandle">The key handle returned by encryption.</param>
    /// <param name="cipher">The nonce[12] + tag[16] + ciphertext artifact.</param>
    /// <param name="plainTextDestination">Destination for decrypted bytes.</param>
    /// <param name="encryptionOptions">Optional AES-GCM decryption settings.</param>
    /// <returns>The number of bytes written to <paramref name="plainTextDestination" />.</returns>
    int Decrypt(
        ulong keyHandle,
        ReadOnlySpan<byte> cipher,
        Span<byte> plainTextDestination,
        EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Encrypts UTF-8 text and returns a {handle}:{Base64(cipher)} payload.
    /// </summary>
    /// <param name="plainText">Text to encrypt.</param>
    /// <param name="encryptionOptions">Optional AES-GCM encryption settings.</param>
    /// <returns>A key-handle-prefixed Base64 cipher artifact.</returns>
    string EncryptText(string plainText, EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Decrypts a {handle}:{Base64(cipher)} payload created by <see cref="EncryptText" />.
    /// </summary>
    /// <param name="encryptedText">A key-handle-prefixed Base64 cipher artifact.</param>
    /// <param name="encryptionOptions">Optional AES-GCM decryption settings.</param>
    /// <returns>The decrypted UTF-8 text.</returns>
    string DecryptText(string encryptedText, EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Computes an unkeyed hash.
    /// </summary>
    /// <param name="dataToHash">Bytes to hash.</param>
    /// <param name="hashOptions">Optional hash settings.</param>
    /// <returns>The computed hash bytes.</returns>
    HashResult Hash(ReadOnlySpan<byte> dataToHash, HashOptions? hashOptions = null);

    /// <summary>
    /// Computes an unkeyed hash into a caller-provided destination buffer.
    /// </summary>
    /// <param name="dataToHash">Bytes to hash.</param>
    /// <param name="hashDestination">Destination for computed hash bytes.</param>
    /// <param name="hashOptions">Optional hash settings.</param>
    /// <returns>The number of bytes written to <paramref name="hashDestination" />.</returns>
    int Hash(ReadOnlySpan<byte> dataToHash, Span<byte> hashDestination, HashOptions? hashOptions = null);

    /// <summary>
    /// Validates an unkeyed hash using fixed-time comparison.
    /// </summary>
    /// <param name="dataToHash">Bytes to hash.</param>
    /// <param name="expectedHash">Expected hash bytes.</param>
    /// <param name="hashOptions">Optional hash settings.</param>
    /// <returns><see langword="true" /> when the computed hash matches <paramref name="expectedHash" />.</returns>
    bool ValidateHash(ReadOnlySpan<byte> dataToHash, ReadOnlySpan<byte> expectedHash, HashOptions? hashOptions = null);

    /// <summary>
    /// Computes an HMAC and returns the replay key handle.
    /// </summary>
    /// <param name="dataToAuthenticate">Bytes to authenticate.</param>
    /// <param name="hmacOptions">Optional HMAC settings.</param>
    /// <returns>The key handle and HMAC bytes.</returns>
    /// <remarks>The HMAC is computed over exactly <paramref name="dataToAuthenticate" />. The key handle is returned as replay metadata.</remarks>
    HmacResult Hmac(ReadOnlySpan<byte> dataToAuthenticate, HmacOptions? hmacOptions = null);

    /// <summary>
    /// Computes an HMAC into a caller-provided destination buffer.
    /// </summary>
    /// <param name="dataToAuthenticate">Bytes to authenticate.</param>
    /// <param name="hmacDestination">Destination for computed HMAC bytes.</param>
    /// <param name="keyHandle">Receives the KeyManager handle required for validation.</param>
    /// <param name="hmacOptions">Optional HMAC settings.</param>
    /// <returns>The number of bytes written to <paramref name="hmacDestination" />.</returns>
    /// <remarks>The HMAC is computed over exactly <paramref name="dataToAuthenticate" />. The key handle is returned as replay metadata.</remarks>
    int Hmac(
        ReadOnlySpan<byte> dataToAuthenticate,
        Span<byte> hmacDestination,
        out ulong keyHandle,
        HmacOptions? hmacOptions = null);

    /// <summary>
    /// Validates an HMAC using replayed KeyManager key material and fixed-time comparison.
    /// </summary>
    /// <param name="keyHandle">The key handle returned by HMAC creation.</param>
    /// <param name="authenticatedData">Bytes that were authenticated.</param>
    /// <param name="expectedHmac">Expected HMAC bytes.</param>
    /// <param name="hmacOptions">Optional HMAC settings.</param>
    /// <returns><see langword="true" /> when the computed HMAC matches <paramref name="expectedHmac" />.</returns>
    bool ValidateHmac(
        ulong keyHandle,
        ReadOnlySpan<byte> authenticatedData,
        ReadOnlySpan<byte> expectedHmac,
        HmacOptions? hmacOptions = null);
}
