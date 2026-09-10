namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Provides usage-agnostic cryptographic operations backed by KeyManager-supplied key material.
/// </summary>
/// <remarks>Operations generating keys require an Enabled KeyManager source. Decryption, verification and
/// deterministic HMAC replay also support Disabled and Retired sources. KeyManager owns lifecycle enforcement;
/// EncryptionManager does not load configuration or deliver audit records.</remarks>
public interface ICryptographicService {
    /// <summary>Protects data using ML-KEM key establishment and AES-256-GCM.</summary>
    EncryptionResult EncryptPostQuantum(byte keySourceId, ReadOnlySpan<byte> dataToEncrypt, PostQuantumEncryptionOptions options);

    /// <summary>Recovers data protected by <see cref="EncryptPostQuantum"/>.</summary>
    byte[] DecryptPostQuantum(ulong keyHandle, ReadOnlySpan<byte> protectedData, PostQuantumEncryptionOptions options);

    /// <summary>Attempts PQC decryption and returns known data, authentication, or key failures without throwing.</summary>
    CryptographicResult<byte[]> TryDecryptPostQuantum(ulong keyHandle, ReadOnlySpan<byte> protectedData, PostQuantumEncryptionOptions options);

    /// <summary>Signs data using ML-DSA seed material supplied by KeyManager.</summary>
    SignatureResult SignPostQuantum(byte keySourceId, ReadOnlySpan<byte> dataToSign, PostQuantumSignatureOptions options);

    /// <summary>Verifies an ML-DSA signature using seed material replayed by KeyManager.</summary>
    bool VerifyPostQuantum(ulong keyHandle, ReadOnlySpan<byte> signedData, ReadOnlySpan<byte> signature, PostQuantumSignatureOptions options);

    /// <summary>
    /// Encrypts bytes with AES-GCM and returns the replay key handle with the cipher artifact.
    /// </summary>
    /// <param name="keySourceId">The configured KeyManager source used to generate key material.</param>
    /// <param name="dataToEncrypt">Bytes to encrypt.</param>
    /// <param name="encryptionOptions">Optional AES-GCM encryption settings.</param>
    /// <returns>The key handle and cipher artifact.</returns>
    /// <remarks>The cipher artifact layout is nonce[12] + tag[16] + ciphertext.</remarks>
    EncryptionResult Encrypt(byte keySourceId, ReadOnlySpan<byte> dataToEncrypt, EncryptionOptions? encryptionOptions = null);

    /// <summary>
    /// Encrypts bytes with AES-GCM into a caller-provided destination buffer.
    /// </summary>
    /// <param name="keySourceId">The configured KeyManager source used to generate key material.</param>
    /// <param name="dataToEncrypt">Bytes to encrypt.</param>
    /// <param name="cipherDestination">Destination for nonce[12] + tag[16] + ciphertext.</param>
    /// <param name="keyHandle">Receives the KeyManager handle required for decryption.</param>
    /// <param name="encryptionOptions">Optional AES-GCM encryption settings.</param>
    /// <returns>The number of bytes written to <paramref name="cipherDestination" />.</returns>
    int Encrypt(
        byte keySourceId,
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
    /// <param name="keySourceId">The configured KeyManager source used to generate key material.</param>
    /// <param name="plainText">Text to encrypt.</param>
    /// <param name="encryptionOptions">Optional AES-GCM encryption settings.</param>
    /// <returns>A key-handle-prefixed Base64 cipher artifact.</returns>
    string EncryptText(byte keySourceId, string plainText, EncryptionOptions? encryptionOptions = null);

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
    /// <param name="keySourceId">The configured KeyManager source used to generate HMAC key material.</param>
    /// <param name="dataToAuthenticate">Bytes to authenticate.</param>
    /// <param name="hmacOptions">Optional HMAC settings.</param>
    /// <returns>The key handle and HMAC bytes.</returns>
    /// <remarks>The HMAC is computed over exactly <paramref name="dataToAuthenticate" />. The key handle is returned as replay metadata.</remarks>
    HmacResult Hmac(byte keySourceId, ReadOnlySpan<byte> dataToAuthenticate, HmacOptions? hmacOptions = null);

    /// <summary>
    /// Computes an HMAC into a caller-provided destination buffer.
    /// </summary>
    /// <param name="keySourceId">The configured KeyManager source used to generate HMAC key material.</param>
    /// <param name="dataToAuthenticate">Bytes to authenticate.</param>
    /// <param name="hmacDestination">Destination for computed HMAC bytes.</param>
    /// <param name="keyHandle">Receives the KeyManager handle required for validation.</param>
    /// <param name="hmacOptions">Optional HMAC settings.</param>
    /// <returns>The number of bytes written to <paramref name="hmacDestination" />.</returns>
    /// <remarks>The HMAC is computed over exactly <paramref name="dataToAuthenticate" />. The key handle is returned as replay metadata.</remarks>
    int Hmac(
        byte keySourceId,
        ReadOnlySpan<byte> dataToAuthenticate,
        Span<byte> hmacDestination,
        out ulong keyHandle,
        HmacOptions? hmacOptions = null);

    /// <summary>
    /// Computes a deterministic HMAC by replaying externally provisioned KeyManager key material.
    /// </summary>
    /// <param name="keyHandle">The stable KeyManager handle identifying the HMAC key material.</param>
    /// <param name="dataToAuthenticate">Bytes to authenticate.</param>
    /// <param name="hmacOptions">Optional HMAC settings. These must match key provisioning.</param>
    /// <returns>The computed HMAC bytes. The key handle is not included in the result.</returns>
    /// <remarks>Replays an existing key without generating one. Enabled, Disabled and Retired sources are supported, including for new lookup inputs.</remarks>
    byte[] HmacWithKeyHandle(
        ulong keyHandle,
        ReadOnlySpan<byte> dataToAuthenticate,
        HmacOptions? hmacOptions = null);

    /// <summary>
    /// Computes a deterministic HMAC into a caller-provided destination by replaying externally provisioned KeyManager key material.
    /// </summary>
    /// <param name="keyHandle">The stable KeyManager handle identifying the HMAC key material.</param>
    /// <param name="dataToAuthenticate">Bytes to authenticate.</param>
    /// <param name="hmacDestination">Destination for the computed HMAC bytes.</param>
    /// <param name="hmacOptions">Optional HMAC settings. These must match key provisioning.</param>
    /// <returns>The number of bytes written to <paramref name="hmacDestination" />.</returns>
    /// <remarks>Replays an existing key without generating one. Enabled, Disabled and Retired sources are supported.</remarks>
    int HmacWithKeyHandle(
        ulong keyHandle,
        ReadOnlySpan<byte> dataToAuthenticate,
        Span<byte> hmacDestination,
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
