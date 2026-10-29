using System.Buffers.Binary;
using System.Globalization;

namespace UsenetSharp.Encryption;

/// <summary>
/// Parsed <c>=yencryption</c> line (Body Standard v1.2 §4 canonical grammar).
/// </summary>
public sealed record YencryptionLine(byte[] Salt, uint SegmentIndex, byte[] Tag);

/// <summary>
/// Strict <c>=yencryption</c> grammar parser: five tokens, single SP separators,
/// lowercase hex, exact lengths (128 chars), cipher=XChaCha20-Poly1305, index != 0
/// and no 0x0A/0x0D inside the big-endian index bytes. All violations are
/// provider-failover and are raised before any KDF work.
/// </summary>
public static class YencryptionLineParser
{
    public const int LineLength = 128;

    public static YencryptionLine Parse(ReadOnlySpan<byte> lineContent)
    {
        // Strip a single trailing terminator already handled by callers; be tolerant of CRLF/LF here.
        if (lineContent.Length >= 2 && lineContent[^2] == (byte)'\r' && lineContent[^1] == (byte)'\n')
        {
            lineContent = lineContent[..^2];
        }
        else if (lineContent.Length >= 1 && (lineContent[^1] == (byte)'\n' || lineContent[^1] == (byte)'\r'))
        {
            lineContent = lineContent[..^1];
        }

        if (lineContent.Length != LineLength)
        {
            throw new YencEncryptionFailoverException(
                string.Create(CultureInfo.InvariantCulture, $"INVALID_LENGTH: =yencryption must be exactly 128 chars, got {lineContent.Length}"));
        }

        // Must be ASCII.
        foreach (var b in lineContent)
        {
            if (b > 0x7F)
            {
                throw new YencEncryptionFailoverException("INVALID_HEX: =yencryption must be ASCII");
            }
        }

        var line = System.Text.Encoding.ASCII.GetString(lineContent);

        // Strict single-SP: tabs, double spaces, leading/trailing space all change the split.
        if (line.Contains('\t', StringComparison.Ordinal) || line.StartsWith(' ') || line.EndsWith(' ') || line.Contains("  ", StringComparison.Ordinal))
        {
            throw new YencEncryptionFailoverException("INVALID_WHITESPACE: =yencryption requires exactly 4 single-SP separators");
        }

        var tokens = line.Split(' ');
        if (tokens.Length != 5 || Array.Exists(tokens, static t => t.Length == 0))
        {
            throw new YencEncryptionFailoverException("INVALID_TOKEN_COUNT: =yencryption requires exactly 5 tokens");
        }

        if (!string.Equals(tokens[0], "=yencryption", StringComparison.Ordinal))
        {
            throw new YencEncryptionFailoverException("INVALID_PREFIX: =yencryption first token mismatch");
        }

        if (!string.Equals(tokens[1], "cipher=XChaCha20-Poly1305", StringComparison.Ordinal))
        {
            throw new YencEncryptionFailoverException("UNSUPPORTED_CIPHER: =yencryption cipher must be XChaCha20-Poly1305");
        }

        if (!tokens[2].StartsWith("salt=", StringComparison.Ordinal))
        {
            throw new YencEncryptionFailoverException("INVALID_TOKEN_ORDER: =yencryption third token must be salt=");
        }

        if (!tokens[3].StartsWith("index=", StringComparison.Ordinal))
        {
            throw new YencEncryptionFailoverException("INVALID_TOKEN_ORDER: =yencryption fourth token must be index=");
        }

        if (!tokens[4].StartsWith("tag=", StringComparison.Ordinal))
        {
            throw new YencEncryptionFailoverException("INVALID_TOKEN_ORDER: =yencryption fifth token must be tag=");
        }

        var saltHex = tokens[2].AsSpan(5);
        var indexHex = tokens[3].AsSpan(6);
        var tagHex = tokens[4].AsSpan(4);

        if (saltHex.Length != 32)
        {
            throw new YencEncryptionFailoverException("INVALID_SALT_LENGTH: salt must be 32 hex chars");
        }

        if (indexHex.Length != 8)
        {
            throw new YencEncryptionFailoverException("INVALID_INDEX_LENGTH: index must be 8 hex chars");
        }

        if (tagHex.Length != 32)
        {
            throw new YencEncryptionFailoverException("INVALID_TAG_LENGTH: tag must be 32 hex chars");
        }

        // Uppercase check gives the more specific token; still failover.
        if (HasUpperHex(saltHex) || HasUpperHex(indexHex) || HasUpperHex(tagHex))
        {
            throw new YencEncryptionFailoverException("UPPERCASE_HEX: =yencryption hex must be lowercase");
        }

        if (!IsLowerHex(saltHex))
        {
            throw new YencEncryptionFailoverException("INVALID_SALT_HEX: salt must be lowercase hex");
        }

        if (!IsLowerHex(indexHex))
        {
            throw new YencEncryptionFailoverException("INVALID_INDEX_HEX: index must be lowercase hex");
        }

        if (!IsLowerHex(tagHex))
        {
            throw new YencEncryptionFailoverException("INVALID_TAG_HEX: tag must be lowercase hex");
        }

        var salt = Convert.FromHexString(saltHex);
        var tag = Convert.FromHexString(tagHex);
        var index = uint.Parse(indexHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        if (index == 0)
        {
            throw new YencEncryptionFailoverException("ZERO_SEGMENT_INDEX: segment index cannot be zero");
        }

        Span<byte> idxBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(idxBytes, index);
        if (idxBytes.Contains((byte)0x0A) || idxBytes.Contains((byte)0x0D))
        {
            throw new YencEncryptionFailoverException("FORBIDDEN_SEGMENT_INDEX_BYTE: segment index contains 0x0A or 0x0D");
        }

        return new YencryptionLine(salt, index, tag);
    }

    private static bool HasUpperHex(ReadOnlySpan<char> s)
    {
        foreach (var c in s)
        {
            if (c is >= 'A' and <= 'F')
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLowerHex(ReadOnlySpan<char> s)
    {
        foreach (var c in s)
        {
            if (!((c is >= '0' and <= '9') || (c is >= 'a' and <= 'f')))
            {
                return false;
            }
        }

        return true;
    }
}
