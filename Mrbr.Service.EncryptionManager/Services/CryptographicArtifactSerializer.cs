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
        if (delimiterIndex <= 0) {
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
}
