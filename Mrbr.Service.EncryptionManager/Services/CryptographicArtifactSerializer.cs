using System.Globalization;
using System.Text;

namespace Mrbr.Service.EncryptionManager.Services;

/// <summary>
/// Serializes and parses common binary and text shapes for cryptographic artifacts.
/// </summary>
public static class CryptographicArtifactSerializer {
    private const char Delimiter = ':';
    private const byte DelimiterByte = (byte)':';

    /// <summary>
    /// Copies the cipher artifact from an encryption result.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>A copy of the cipher artifact bytes.</returns>
    public static byte[] ToCipherBytes(this EncryptionResult result) => GetCipher(result).ToArray();

    /// <summary>
    /// Encodes an encryption result cipher artifact as Base64 text.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>The Base64-encoded cipher artifact.</returns>
    public static string ToCipherBase64(this EncryptionResult result) => ToBase64(GetCipher(result));

    /// <summary>
    /// Encodes an encryption result cipher artifact as uppercase hexadecimal text.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>The hexadecimal cipher artifact.</returns>
    public static string ToCipherHex(this EncryptionResult result) => ToHex(GetCipher(result));

    /// <summary>
    /// Encodes an encryption result as ASCII {handle}: followed by raw cipher artifact bytes.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>The key-handle-prefixed raw cipher artifact bytes.</returns>
    public static byte[] ToKeyHandleCipherBytes(this EncryptionResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return ToKeyHandleArtifactBytes(result.KeyHandle, GetCipher(result));
    }

    /// <summary>
    /// Encodes an encryption result as {handle}:{Base64(cipher)}.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>The key-handle-prefixed Base64 cipher artifact.</returns>
    public static string ToKeyHandleCipherBase64(this EncryptionResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return ToKeyHandleBase64(result.KeyHandle, GetCipher(result));
    }

    /// <summary>
    /// Encodes an encryption result as {handle}:{Hex(cipher)}.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>The key-handle-prefixed hexadecimal cipher artifact.</returns>
    public static string ToKeyHandleCipherHex(this EncryptionResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return ToKeyHandleHex(result.KeyHandle, GetCipher(result));
    }

    /// <summary>
    /// Converts an encryption result to a structured keyed artifact.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <returns>The key handle and a copy of the cipher artifact bytes.</returns>
    public static KeyedCryptographicArtifact ToKeyedArtifact(this EncryptionResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return new KeyedCryptographicArtifact(result.KeyHandle, ToCipherBytes(result));
    }

    /// <summary>
    /// Encodes an encryption result to a binary artifact format.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <param name="format">The binary artifact format.</param>
    /// <returns>The serialized artifact bytes.</returns>
    public static byte[] ToArtifactBytes(this EncryptionResult result, CryptographicArtifactFormat format) =>
        format switch {
            CryptographicArtifactFormat.Raw => ToCipherBytes(result),
            CryptographicArtifactFormat.KeyHandleRaw => ToKeyHandleCipherBytes(result),
            _ => throw new NotSupportedException($"Artifact format '{format}' is text. Use ToArtifactText.")
        };

    /// <summary>
    /// Encodes an encryption result to a text artifact format.
    /// </summary>
    /// <param name="result">The encryption result.</param>
    /// <param name="format">The text artifact format.</param>
    /// <returns>The serialized artifact text.</returns>
    public static string ToArtifactText(this EncryptionResult result, CryptographicArtifactFormat format) =>
        format switch {
            CryptographicArtifactFormat.Base64 => ToCipherBase64(result),
            CryptographicArtifactFormat.Hex => ToCipherHex(result),
            CryptographicArtifactFormat.KeyHandleBase64 => ToKeyHandleCipherBase64(result),
            CryptographicArtifactFormat.KeyHandleHex => ToKeyHandleCipherHex(result),
            _ => throw new NotSupportedException($"Artifact format '{format}' is binary. Use ToArtifactBytes.")
        };

    /// <summary>
    /// Copies the HMAC artifact from an HMAC result.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>A copy of the HMAC bytes.</returns>
    public static byte[] ToHmacBytes(this HmacResult result) => GetHmac(result).ToArray();

    /// <summary>
    /// Encodes an HMAC result artifact as Base64 text.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>The Base64-encoded HMAC artifact.</returns>
    public static string ToHmacBase64(this HmacResult result) => ToBase64(GetHmac(result));

    /// <summary>
    /// Encodes an HMAC result artifact as uppercase hexadecimal text.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>The hexadecimal HMAC artifact.</returns>
    public static string ToHmacHex(this HmacResult result) => ToHex(GetHmac(result));

    /// <summary>
    /// Encodes an HMAC result as ASCII {handle}: followed by raw HMAC bytes.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>The key-handle-prefixed raw HMAC bytes.</returns>
    public static byte[] ToKeyHandleHmacBytes(this HmacResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return ToKeyHandleArtifactBytes(result.KeyHandle, GetHmac(result));
    }

    /// <summary>
    /// Encodes an HMAC result as {handle}:{Base64(hmac)}.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>The key-handle-prefixed Base64 HMAC artifact.</returns>
    public static string ToKeyHandleHmacBase64(this HmacResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return ToKeyHandleBase64(result.KeyHandle, GetHmac(result));
    }

    /// <summary>
    /// Encodes an HMAC result as {handle}:{Hex(hmac)}.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>The key-handle-prefixed hexadecimal HMAC artifact.</returns>
    public static string ToKeyHandleHmacHex(this HmacResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return ToKeyHandleHex(result.KeyHandle, GetHmac(result));
    }

    /// <summary>
    /// Converts an HMAC result to a structured keyed artifact.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <returns>The key handle and a copy of the HMAC bytes.</returns>
    public static KeyedCryptographicArtifact ToKeyedArtifact(this HmacResult result) {
        ArgumentNullException.ThrowIfNull(result);
        return new KeyedCryptographicArtifact(result.KeyHandle, ToHmacBytes(result));
    }

    /// <summary>
    /// Encodes an HMAC result to a binary artifact format.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <param name="format">The binary artifact format.</param>
    /// <returns>The serialized artifact bytes.</returns>
    public static byte[] ToArtifactBytes(this HmacResult result, CryptographicArtifactFormat format) =>
        format switch {
            CryptographicArtifactFormat.Raw => ToHmacBytes(result),
            CryptographicArtifactFormat.KeyHandleRaw => ToKeyHandleHmacBytes(result),
            _ => throw new NotSupportedException($"Artifact format '{format}' is text. Use ToArtifactText.")
        };

    /// <summary>
    /// Encodes an HMAC result to a text artifact format.
    /// </summary>
    /// <param name="result">The HMAC result.</param>
    /// <param name="format">The text artifact format.</param>
    /// <returns>The serialized artifact text.</returns>
    public static string ToArtifactText(this HmacResult result, CryptographicArtifactFormat format) =>
        format switch {
            CryptographicArtifactFormat.Base64 => ToHmacBase64(result),
            CryptographicArtifactFormat.Hex => ToHmacHex(result),
            CryptographicArtifactFormat.KeyHandleBase64 => ToKeyHandleHmacBase64(result),
            CryptographicArtifactFormat.KeyHandleHex => ToKeyHandleHmacHex(result),
            _ => throw new NotSupportedException($"Artifact format '{format}' is binary. Use ToArtifactBytes.")
        };

    /// <summary>
    /// Encodes an artifact as Base64 text.
    /// </summary>
    /// <param name="artifact">Artifact bytes to encode.</param>
    /// <returns>The Base64-encoded artifact.</returns>
    public static string ToBase64(ReadOnlySpan<byte> artifact) => Convert.ToBase64String(artifact);

    /// <summary>
    /// Parses a Base64-encoded artifact.
    /// </summary>
    /// <param name="artifact">The Base64-encoded artifact.</param>
    /// <returns>The parsed artifact bytes.</returns>
    public static byte[] FromBase64(string artifact) => Convert.FromBase64String(artifact);

    /// <summary>
    /// Encodes an artifact as uppercase hexadecimal text.
    /// </summary>
    /// <param name="artifact">Artifact bytes to encode.</param>
    /// <returns>The hexadecimal artifact.</returns>
    public static string ToHex(ReadOnlySpan<byte> artifact) => Convert.ToHexString(artifact);

    /// <summary>
    /// Parses a hexadecimal artifact.
    /// </summary>
    /// <param name="artifact">The hexadecimal artifact.</param>
    /// <returns>The parsed artifact bytes.</returns>
    public static byte[] FromHex(string artifact) => Convert.FromHexString(artifact);

    /// <summary>
    /// Encodes a key handle and artifact as {handle}:{Base64(artifact)}.
    /// </summary>
    /// <param name="keyHandle">The KeyManager handle to prefix.</param>
    /// <param name="artifact">Artifact bytes to encode.</param>
    /// <returns>The key-handle-prefixed Base64 artifact.</returns>
    public static string ToKeyHandleBase64(ulong keyHandle, ReadOnlySpan<byte> artifact) =>
        string.Create(CultureInfo.InvariantCulture, $"{keyHandle}{Delimiter}{Convert.ToBase64String(artifact)}");

    /// <summary>
    /// Parses a {handle}:{Base64(artifact)} payload.
    /// </summary>
    /// <param name="artifact">The key-handle-prefixed Base64 artifact.</param>
    /// <returns>The parsed key handle and artifact bytes.</returns>
    public static KeyedCryptographicArtifact FromKeyHandleBase64(string artifact) {
        var (keyHandle, encodedArtifact) = SplitKeyHandleArtifact(artifact);
        return new KeyedCryptographicArtifact(keyHandle, Convert.FromBase64String(encodedArtifact));
    }

    /// <summary>
    /// Encodes a key handle and artifact as {handle}:{Hex(artifact)}.
    /// </summary>
    /// <param name="keyHandle">The KeyManager handle to prefix.</param>
    /// <param name="artifact">Artifact bytes to encode.</param>
    /// <returns>The key-handle-prefixed hexadecimal artifact.</returns>
    public static string ToKeyHandleHex(ulong keyHandle, ReadOnlySpan<byte> artifact) =>
        string.Create(CultureInfo.InvariantCulture, $"{keyHandle}{Delimiter}{Convert.ToHexString(artifact)}");

    /// <summary>
    /// Parses a {handle}:{Hex(artifact)} payload.
    /// </summary>
    /// <param name="artifact">The key-handle-prefixed hexadecimal artifact.</param>
    /// <returns>The parsed key handle and artifact bytes.</returns>
    public static KeyedCryptographicArtifact FromKeyHandleHex(string artifact) {
        var (keyHandle, encodedArtifact) = SplitKeyHandleArtifact(artifact);
        return new KeyedCryptographicArtifact(keyHandle, Convert.FromHexString(encodedArtifact));
    }

    /// <summary>
    /// Encodes a key handle and raw artifact bytes as ASCII {handle}: followed by artifact bytes.
    /// </summary>
    /// <param name="keyHandle">The KeyManager handle to prefix.</param>
    /// <param name="artifact">Artifact bytes to append.</param>
    /// <returns>The key-handle-prefixed raw artifact bytes.</returns>
    public static byte[] ToKeyHandleArtifactBytes(ulong keyHandle, ReadOnlySpan<byte> artifact) {
        byte[] prefix = Encoding.ASCII.GetBytes(keyHandle.ToString(CultureInfo.InvariantCulture) + Delimiter);
        byte[] result = GC.AllocateUninitializedArray<byte>(prefix.Length + artifact.Length);
        prefix.CopyTo(result.AsSpan(0, prefix.Length));
        artifact.CopyTo(result.AsSpan(prefix.Length));
        return result;
    }

    /// <summary>
    /// Parses ASCII {handle}: followed by raw artifact bytes.
    /// </summary>
    /// <param name="artifact">The key-handle-prefixed raw artifact bytes.</param>
    /// <returns>The parsed key handle and artifact bytes.</returns>
    public static KeyedCryptographicArtifact FromKeyHandleArtifactBytes(ReadOnlySpan<byte> artifact) {
        int delimiterIndex = artifact.IndexOf(DelimiterByte);
        if (delimiterIndex <= 0 || delimiterIndex == artifact.Length - 1) {
            throw new FormatException("Artifact must be in '{keyHandle}:{artifact}' format.");
        }

        string keyHandleText = Encoding.ASCII.GetString(artifact.Slice(0, delimiterIndex));
        if (ulong.TryParse(keyHandleText, NumberStyles.None, CultureInfo.InvariantCulture, out ulong keyHandle) == false) {
            throw new FormatException("Artifact key handle is not a valid unsigned integer.");
        }

        return new KeyedCryptographicArtifact(keyHandle, artifact.Slice(delimiterIndex + 1).ToArray());
    }

    private static (ulong KeyHandle, string Artifact) SplitKeyHandleArtifact(string artifact) {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifact);

        int delimiterIndex = artifact.IndexOf(Delimiter, StringComparison.Ordinal);
        if (delimiterIndex <= 0 || delimiterIndex == artifact.Length - 1) {
            throw new FormatException("Artifact must be in '{keyHandle}:{artifact}' format.");
        }

        string keyHandleText = artifact[..delimiterIndex];
        if (ulong.TryParse(keyHandleText, NumberStyles.None, CultureInfo.InvariantCulture, out ulong keyHandle) == false) {
            throw new FormatException("Artifact key handle is not a valid unsigned integer.");
        }

        return (keyHandle, artifact[(delimiterIndex + 1)..]);
    }

    private static byte[] GetCipher(EncryptionResult result) {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(result.Cipher);
        return result.Cipher;
    }

    private static byte[] GetHmac(HmacResult result) {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(result.Hmac);
        return result.Hmac;
    }
}
