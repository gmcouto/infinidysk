using RapidYencSharp;
using UsenetSharp.Models;
using UsenetSharp.Streams;

namespace UsenetSharp.Encryption;

/// <summary>
/// Restores one encrypted article, yEnc-decodes the ciphertext body, checks the
/// wire CRC32 over the ciphertext, and opens the AEAD segment. Plaintext is
/// returned only after authentication succeeds and its length matches the AAD
/// segment length; every failure is a provider-failover (or local-fatal KDF)
/// exception with zero plaintext released. Callers must not log plaintext,
/// keys, nonces, or tags obtained here.
/// </summary>
public static class EncryptedYencAssembler
{
    /// <summary>Decoded ciphertext plus restored header geometry for one article.</summary>
    public sealed record DecodedCiphertext(
        byte[] Ciphertext,
        RestoredArticle Restored,
        UsenetYencHeader Headers);

    /// <summary>Authenticated plaintext plus restored header geometry.</summary>
    public sealed record OpenedSegment(
        byte[] Plaintext,
        RestoredArticle Restored,
        UsenetYencHeader Headers);

    /// <summary>Restores, decodes (ciphertext) and CRC-checks one raw article.</summary>
    public static DecodedCiphertext DecodeCiphertext(YencEncryptionContext context, ReadOnlySpan<byte> article)
    {
        var restored = YencControlRestorer.Restore(context, article);
        var stripped = YencControlRestorer.RemoveYencryptionLine(restored.RestoredBlock);
        var lines = YencControlRestorer.SplitLinesPreservingEndings(stripped);

        // The footer is the last non-empty physical line (trailing empties ignored).
        while (lines.Count > 0 && YencControlRestorer.SplitEnding(lines[^1]).Content.Length == 0)
            lines.RemoveAt(lines.Count - 1);

        if (lines.Count < 2)
            throw new YencEncryptionFailoverException("Encrypted article has no =yend trailer.");

        var ybeginContent = YencControlRestorer.SplitEnding(lines[0]).Content;
        var isMultipart = restored.Geometry.IsMultipart;
        var ypartContent = isMultipart
            ? YencControlRestorer.SplitEnding(lines[1]).Content
            : Array.Empty<byte>();
        var headers = ParseRestoredHeaders(ybeginContent, ypartContent, restored);

        var footerContent = YencControlRestorer.SplitEnding(lines[^1]).Content;
        if (!YencStream.StartsWithYEnd(footerContent))
            throw new YencEncryptionFailoverException("Encrypted article has no =yend trailer.");

        var dataStart = isMultipart ? 2 : 1;
        var ciphertext = DecodeDataLines(lines, dataStart);

        // Wire CRC32 (crc32=/pcrc32=) covers the ciphertext (Body/Control v1.2).
        CheckCiphertextCrc(footerContent, isMultipart, ciphertext);

        return new DecodedCiphertext(ciphertext, restored, headers);
    }

    /// <summary>Authenticates and opens decoded ciphertext (AAD from the restore).</summary>
    public static OpenedSegment Open(YencEncryptionContext context, DecodedCiphertext decoded)
    {
        var plaintext = Open(context, decoded.Restored, decoded.Ciphertext);
        if ((ulong)plaintext.Length != decoded.Restored.Geometry.SegmentBytes)
        {
            throw new YencEncryptionFailoverException(
                "Authenticated plaintext length differs from the AAD segment length.");
        }

        return new OpenedSegment(plaintext, decoded.Restored, decoded.Headers);
    }

    /// <summary>Full raw-article → authenticated plaintext transform.</summary>
    public static OpenedSegment OpenArticle(YencEncryptionContext context, ReadOnlySpan<byte> article)
        => Open(context, DecodeCiphertext(context, article));

    private static byte[] Open(
        YencEncryptionContext context, RestoredArticle restored, byte[] ciphertext)
    {
        var master = context.GetMasterKey(restored.Salt);
        return YencBodyCipher.Open(
            master, restored.SegmentIndex, ciphertext, restored.Yencryption.Tag, restored.Aad);
    }

    /// <summary>
    /// Builds the plaintext-world header from the restored keywords. The
    /// restored geometry (not a possibly-obfuscated NZB size) is
    /// authoritative: a header whose part geometry disagrees with the
    /// authenticated AAD length is provider corruption (plan §4.5).
    /// </summary>
    internal static UsenetYencHeader ParseRestoredHeaders(
        ReadOnlySpan<byte> ybeginContent,
        ReadOnlySpan<byte> ypartContent,
        RestoredArticle restored) =>
        ParseRestoredHeaders(ybeginContent, ypartContent, restored.Geometry);

    internal static UsenetYencHeader ParseRestoredHeaders(
        ReadOnlySpan<byte> ybeginContent,
        ReadOnlySpan<byte> ypartContent,
        YencArticleGeometry geometry)
    {
        var headers = YencStream.ParseYencHeaders(ybeginContent, ypartContent);
        if (headers.FileSize < 0 || headers.PartSize < 0 || headers.PartOffset < 0)
            throw new YencEncryptionFailoverException("Restored yEnc header geometry is invalid.");
        if ((ulong)headers.PartSize != geometry.SegmentBytes)
            throw new YencEncryptionFailoverException(
                "Restored yEnc part size disagrees with the authenticated AAD segment length.");
        return headers;
    }

    /// <summary>Wire-CRC check over decoded ciphertext; message shape matches the pump's CRC text.</summary>
    internal static void CheckCiphertextCrc(
        ReadOnlySpan<byte> footerContent, bool isMultipart, ReadOnlySpan<byte> ciphertext)
    {
        if (!TryParseTrailerCrc(footerContent, isMultipart, out var expectedCrc))
            throw new YencEncryptionFailoverException("Encrypted article =yend lacks a CRC32.");
        var actualCrc = Crc32.Compute(ciphertext);
        if (actualCrc != expectedCrc)
        {
            throw new YencEncryptionFailoverException(
                FormattableString.Invariant(
                    $"The decoded yEnc CRC32 was {actualCrc:x8}, but the trailer expected {expectedCrc:x8}."));
        }
    }

    private static byte[] DecodeDataLines(List<byte[]> lines, int dataStart)
    {
        // Data region: every line between the control headers and the footer.
        using var ciphertext = new MemoryStream();
        RapidYencDecoderState? state = RapidYencDecoderState.RYDEC_STATE_CRLF;
        for (var i = dataStart; i < lines.Count - 1; i++)
        {
            var raw = lines[i];
            if (raw.Length == 0)
                continue;
            var chunk = new byte[raw.Length];
            var written = YencDecoder.DecodeEx(raw, chunk, ref state, isRaw: true);
            ciphertext.Write(chunk, 0, written);
        }

        return ciphertext.ToArray();
    }

    private static bool TryParseTrailerCrc(ReadOnlySpan<byte> yendLine, bool isMultipart, out uint crc)
    {
        crc = 0;
        var field = isMultipart ? "pcrc32="u8 : "crc32="u8;
        var position = 0;
        while (position < yendLine.Length)
        {
            while (position < yendLine.Length && IsWhitespace(yendLine[position]))
                position++;
            var start = position;
            while (position < yendLine.Length && !IsWhitespace(yendLine[position]))
                position++;
            var token = yendLine[start..position];
            if (token.StartsWith(field))
            {
                var value = token[field.Length..];
                return System.Buffers.Text.Utf8Parser.TryParse(value, out crc, out var consumed, 'X')
                    && consumed == value.Length;
            }
        }

        return false;
    }

    private static bool IsWhitespace(byte value) => value is (byte)' ' or (byte)'\t';
}
