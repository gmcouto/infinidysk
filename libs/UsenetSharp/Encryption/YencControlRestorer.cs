using System.Buffers.Binary;
using System.Globalization;

namespace UsenetSharp.Encryption;

/// <summary>Line-1 bootstrap: 16-byte salt || uint32be(segmentIndex) (Control §5).</summary>
public sealed record YencBootstrap(byte[] Salt, uint SegmentIndex);

/// <summary>Restored-article geometry needed for the AAD (Body §2.1).</summary>
public sealed record YencArticleGeometry(
    byte[] NameBytes,
    uint PartNumber,
    uint PartBegin,
    ulong SegmentBytes,
    bool IsMultipart);

/// <summary>Result of restoring one combined-mode article.</summary>
public sealed record RestoredArticle(
    byte[] RestoredBlock,
    byte[] Salt,
    uint SegmentIndex,
    YencryptionLine Yencryption,
    YencArticleGeometry Geometry,
    byte[] Aad);

/// <summary>
/// Bootstrap parser, control-line restore, and <c>=yencryption</c>/AAD extraction.
/// Mirrors SABnzbd encryption.py (split_lines_preserving_endings semantics,
/// fixed positions, trailing-empty-lines footer rule). All article-byte
/// failures are provider-failover; no plaintext is released here.
///
/// Known limits (documented, not behaviour changes):
/// (a) A duplicate <c>=yencryption</c> line sitting in the data region is
///     undetectable here: data lines are never FF1-decrypted (they pass
///     through byte-for-byte), so an extra encrypted-looking line there is
///     indistinguishable from ciphertext — parity with SABnzbd, which has
///     the same property. Body §3 duplicate rejection is enforced (in
///     <see cref="ExtractYencryption"/>) for every duplicate visible after
///     restore, i.e. at the fixed position and in the restored control
///     lines. An inert extra line in the data region cannot release
///     plaintext: the AEAD open gates on the single parsed
///     <c>=yencryption</c> line's tag/nonce/AAD, so tampered or extra data
///     bytes fail authentication instead of decrypting.
/// (b) Grammar validation of the restored <c>=yencryption</c> line inside
///     <see cref="Restore"/> necessarily runs after the FF1 key derivation:
///     the line's plaintext grammar is undecidable before the control lines
///     are decrypted, so the KDF must happen first. Where grammar alone
///     suffices without decryption, the static
///     <c>YencryptionLineParser.Parse</c> path validates before any KDF
///     (pinned by Malformed_Yencryption_Lines_Rejected_Before_Kdf).
/// </summary>
public static class YencControlRestorer
{
    public const int BootstrapLength = 20;

    public static YencBootstrap ParseBootstrap(ReadOnlySpan<byte> line1Content)
    {
        if (line1Content.Length < 22)
        {
            throw new YencEncryptionFailoverException("LINE_TRUNCATED: Line 1 shorter than 22 bytes");
        }

        var salt = line1Content[..16].ToArray();
        foreach (var b in salt)
        {
            if (b is 0x00 or 0x0A or 0x0D)
            {
                throw new YencEncryptionFailoverException("INVALID_SALT_CHARACTER: forbidden byte in salt");
            }
        }

        var indexBytes = line1Content[16..20];
        var index = BinaryPrimitives.ReadUInt32BigEndian(indexBytes);
        if (index == 0)
        {
            throw new YencEncryptionFailoverException("ZERO_SEGMENT_INDEX: segment index cannot be zero");
        }

        if (indexBytes.Contains((byte)0x0A) || indexBytes.Contains((byte)0x0D))
        {
            throw new YencEncryptionFailoverException("FORBIDDEN_SEGMENT_INDEX_BYTE: segment index contains 0x0A or 0x0D");
        }

        return new YencBootstrap(salt, index);
    }

    /// <summary>
    /// Restores the control lines of one article. <paramref name="article"/>
    /// is the dot-unstuffed article body with terminators preserved.
    /// </summary>
    public static RestoredArticle Restore(YencEncryptionContext context, ReadOnlySpan<byte> article)
    {
        var lines = SplitLinesPreservingEndings(article);

        // Footer rule: trailing empty physical lines are ignored before counting.
        while (lines.Count > 0 && SplitEnding(lines[^1]).Content.Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        if (lines.Count == 0)
        {
            throw new YencEncryptionFailoverException("Empty encrypted article block");
        }

        var (line1Content, line1Ending) = SplitEnding(lines[0]);
        var bootstrap = ParseBootstrap(line1Content);
        var master = context.GetMasterKey(bootstrap.Salt);
        var controlKey = YencKeySchedule.DeriveControlKey(master);

        var pt1 = DecryptLine(master, controlKey, bootstrap.SegmentIndex, 1, line1Content.AsSpan(BootstrapLength));
        if (!pt1.AsSpan().StartsWith("=ybegin"u8))
        {
            throw new YencEncryptionFailoverException("CONTROL_LINE_DECRYPT_FAILURE: line 1 does not start with =ybegin");
        }

        if (lines.Count < 3)
        {
            throw new YencEncryptionFailoverException("Article block too short for encrypted yEnc (minimum 3 lines)");
        }

        var (line2Content, line2Ending) = SplitEnding(lines[1]);
        var pt2 = DecryptLine(master, controlKey, bootstrap.SegmentIndex, 2, line2Content);

        var (headerTokens, nameBytes) = SplitYbegin(pt1);
        var hasPart = HasPartKeyword(headerTokens);

        var restored = new List<byte[]>(lines.Count);
        restored.Add(Concat(pt1, line1Ending));

        bool isMultipart;
        int yencLineIndex; // 1-based physical line of =yencryption
        int firstDataLine; // 1-based
        if (pt2.AsSpan().StartsWith("=ypart"u8))
        {
            isMultipart = true;
            if (lines.Count < 4)
            {
                throw new YencEncryptionFailoverException("Multipart article too short (minimum 4 lines)");
            }

            if (!hasPart)
            {
                throw new YencEncryptionFailoverException("INVALID_MULTIPART_FRAMING: =ypart on line 2 but =ybegin has no part=");
            }

            restored.Add(Concat(pt2, line2Ending));
            var (line3Content, line3Ending) = SplitEnding(lines[2]);
            var pt3 = DecryptLine(master, controlKey, bootstrap.SegmentIndex, 3, line3Content);
            if (!pt3.AsSpan().StartsWith("=yencryption"u8))
            {
                throw new YencEncryptionFailoverException("Line 3 is not =yencryption at its fixed position");
            }

            restored.Add(Concat(pt3, line3Ending));
            yencLineIndex = 3;
            firstDataLine = 4;
        }
        else if (pt2.AsSpan().StartsWith("=yencryption"u8))
        {
            isMultipart = false;
            if (hasPart)
            {
                throw new YencEncryptionFailoverException("MISPLACED_ENCRYPTION_HEADER: =yencryption on line 2 but =ybegin has part=");
            }

            restored.Add(Concat(pt2, line2Ending));
            yencLineIndex = 2;
            firstDataLine = 3;
        }
        else
        {
            throw new YencEncryptionFailoverException("CONTROL_LINE_DECRYPT_FAILURE: line 2 is neither =ypart nor =yencryption");
        }

        // Data lines D..N-1 pass through byte-for-byte, terminators included.
        for (var i = firstDataLine - 1; i < lines.Count - 1; i++)
        {
            restored.Add(lines[i]);
        }

        // Footer is the last non-empty physical line (position N).
        var (footerContent, footerEnding) = SplitEnding(lines[^1]);
        var ptFooter = DecryptLine(master, controlKey, bootstrap.SegmentIndex, (uint)lines.Count, footerContent);
        if (!ptFooter.AsSpan().StartsWith("=yend"u8))
        {
            throw new YencEncryptionFailoverException("CONTROL_LINE_DECRYPT_FAILURE: footer does not start with =yend");
        }

        restored.Add(Concat(ptFooter, footerEnding));

        var restoredBlock = ConcatAll(restored);

        // Parse =yencryption from the restored block, enforce single occurrence + dual bootstrap.
        var (yenc, geometry, aad) = ExtractYencryption(restoredBlock, isMultipart);
        if (!yenc.Salt.AsSpan().SequenceEqual(bootstrap.Salt))
        {
            throw new YencEncryptionFailoverException("DUAL_SALT_MISMATCH: Line 1 salt != =yencryption salt");
        }

        if (yenc.SegmentIndex != bootstrap.SegmentIndex)
        {
            throw new YencEncryptionFailoverException("DUAL_INDEX_MISMATCH: Line 1 index != =yencryption index");
        }

        _ = yencLineIndex;
        return new RestoredArticle(restoredBlock, bootstrap.Salt, bootstrap.SegmentIndex, yenc, geometry, aad);
    }

    /// <summary>
    /// The plain (unencrypted) =yencryption line at its fixed position against a
    /// caller-supplied master key — validation for the already-restored block
    /// (INF-15); same grammar/geometry as <see cref="ExtractYencryption"/>.
    /// </summary>
    internal static (YencryptionLine Yenc, YencArticleGeometry Geometry, byte[] Aad) ExtractYencryptionFromRestored(
        ReadOnlySpan<byte> restoredBlock, bool? expectMultipart = null) =>
        ExtractYencryption(restoredBlock, expectMultipart);

    internal static (YencryptionLine Yenc, YencArticleGeometry Geometry, byte[] Aad) ExtractYencryption(
        ReadOnlySpan<byte> restoredBlock, bool? expectMultipart = null)
    {
        var lines = SplitLinesPreservingEndings(restoredBlock);
        if (lines.Count < 2)
        {
            throw new YencEncryptionFailoverException("Article block too short");
        }

        var line1 = SplitEnding(lines[0]).Content;
        if (!line1.StartsWith("=ybegin"u8))
        {
            throw new YencEncryptionFailoverException("Line 1 does not start with =ybegin");
        }

        var (headerTokens, nameBytes) = SplitYbegin(line1.ToArray());
        if (nameBytes is null || nameBytes.Length == 0)
        {
            throw new YencEncryptionFailoverException("MISSING_AAD_SUBJECT: =ybegin name parameter is required");
        }

        var hasPart = HasPartKeyword(headerTokens);
        var line2 = SplitEnding(lines[1]).Content;
        bool isMultipart;
        int yencIdx;
        if (line2.StartsWith("=ypart"u8))
        {
            isMultipart = true;
            if (!hasPart)
            {
                throw new YencEncryptionFailoverException("INVALID_MULTIPART_FRAMING: =ypart on line 2 but =ybegin has no part=");
            }

            if (lines.Count < 3)
            {
                throw new YencEncryptionFailoverException("Multipart article too short");
            }

            if (!SplitEnding(lines[2]).Content.StartsWith("=yencryption"u8))
            {
                throw new YencEncryptionFailoverException("Line 3 in multipart article does not start with =yencryption");
            }

            yencIdx = 2;
        }
        else if (line2.StartsWith("=yencryption"u8))
        {
            isMultipart = false;
            if (hasPart)
            {
                throw new YencEncryptionFailoverException("MISPLACED_ENCRYPTION_HEADER: =yencryption on line 2 but =ybegin has part=");
            }

            yencIdx = 1;
        }
        else
        {
            throw new YencEncryptionFailoverException("Line 2 does not start with =yencryption or =ypart");
        }

        if (expectMultipart.HasValue && expectMultipart.Value != isMultipart)
        {
            throw new YencEncryptionFailoverException("MISPLACED_ENCRYPTION_HEADER: framing mismatch");
        }

        for (var i = 0; i < lines.Count; i++)
        {
            if (i != yencIdx && SplitEnding(lines[i]).Content.StartsWith("=yencryption"u8))
            {
                throw new YencEncryptionFailoverException($"Duplicate or misplaced =yencryption at line {i + 1}");
            }
        }

        var yenc = YencryptionLineParser.Parse(SplitEnding(lines[yencIdx]).Content);

        var ybeginValues = KeywordValues(headerTokens);
        uint partNumber;
        uint partBegin;
        ulong segmentBytes;
        if (isMultipart)
        {
            partNumber = RequiredUInt(ybeginValues, "part", "=ybegin");
            var ypartValues = KeywordValues(SplitTokens(SplitEnding(lines[1]).Content));
            var begin = RequiredUInt(ypartValues, "begin", "=ypart");
            var end = RequiredUInt(ypartValues, "end", "=ypart");
            if (begin < 1)
            {
                throw new YencEncryptionFailoverException("=ypart begin is less than 1");
            }

            if (end < begin)
            {
                throw new YencEncryptionFailoverException("=ypart end is before begin");
            }

            partBegin = begin;
            segmentBytes = (ulong)(end - begin + 1);
            // RequiredUInt already rejected any value >= 2^32 during parsing.
        }
        else
        {
            partNumber = 1;
            partBegin = 1;
            segmentBytes = RequiredUInt(ybeginValues, "size", "=ybegin");
        }

        if (ybeginValues.TryGetValue("size", out var sizeRaw))
        {
            var sizeVal = ParseUIntToken(sizeRaw, "=ybegin size=");
            if (sizeVal >= (1UL << 32))
            {
                throw new YencEncryptionFailoverException("SIZE_OVERFLOW: size exceeds 4 GiB");
            }
        }

        var geometry = new YencArticleGeometry(nameBytes, partNumber, partBegin, segmentBytes, isMultipart);
        var aad = YencAad.Build(nameBytes, partNumber, partBegin, segmentBytes);
        return (yenc, geometry, aad);
    }

    /// <summary>Returns the restored block with the =yencryption line removed (for ordinary yEnc decode).</summary>
    public static byte[] RemoveYencryptionLine(ReadOnlySpan<byte> restoredBlock)
    {
        var lines = SplitLinesPreservingEndings(restoredBlock);
        var line2 = lines.Count > 1 ? SplitEnding(lines[1]).Content : default;
        var idx = line2.StartsWith("=ypart"u8) ? 2 : 1;
        lines.RemoveAt(idx);
        return ConcatAll(lines);
    }

    // --- helpers mirroring SABnzbd ---

    internal static List<byte[]> SplitLinesPreservingEndings(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0)
        {
            throw new YencEncryptionFailoverException("Empty encrypted article block");
        }

        var lines = new List<byte[]>();
        var pos = 0;
        while (pos < input.Length)
        {
            var start = pos;
            if (lines.Count == 0)
            {
                pos += Math.Min(BootstrapLength, input.Length);
            }

            var idx = input[pos..].IndexOf((byte)'\n');
            if (idx >= 0)
            {
                pos += idx + 1;
                lines.Add(input[start..pos].ToArray());
            }
            else
            {
                lines.Add(input[start..].ToArray());
                break;
            }
        }

        return lines;
    }

    internal static (byte[] Content, byte[] Ending) SplitEnding(ReadOnlySpan<byte> line)
    {
        if (line.Length >= 2 && line[^2] == (byte)'\r' && line[^1] == (byte)'\n')
        {
            return (line[..^2].ToArray(), line[^2..].ToArray());
        }

        if (line.Length >= 1 && line[^1] == (byte)'\n')
        {
            return (line[..^1].ToArray(), line[^1..].ToArray());
        }

        return (line.ToArray(), []);
    }

    private static byte[] DecryptLine(byte[] master, byte[] controlKey, uint segIndex, uint lineIndex, ReadOnlySpan<byte> content)
    {
        _ = master;
        var tweak = YencKeySchedule.DeriveControlTweak(master, segIndex, lineIndex);
        return YencFf1.Decrypt(controlKey, tweak, content);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    private static byte[] ConcatAll(List<byte[]> parts)
    {
        var total = 0;
        foreach (var p in parts)
        {
            total += p.Length;
        }

        var r = new byte[total];
        var off = 0;
        foreach (var p in parts)
        {
            p.CopyTo(r, off);
            off += p.Length;
        }

        return r;
    }

    internal static (List<byte[]> TokensBeforeName, byte[]? Name) SplitYbegin(byte[] line1)
    {
        var content = SplitEnding(line1).Content;
        // Find " name=" or leading "name=" — name value is remainder of line.
        var idx = IndexOfNameKeyword(content);
        if (idx < 0)
        {
            return (SplitTokens(content), null);
        }

        var nameStart = idx + 5; // len("name=") offset computed by caller below
        // idx points at the space (or 0); locate '=' then +1
        var eq = Array.IndexOf(content, (byte)'=', idx);
        var name = content[(eq + 1)..];
        var tokens = SplitTokens(content.AsSpan(0, idx).ToArray());
        _ = nameStart;
        return (tokens, name);
    }

    private static int IndexOfNameKeyword(byte[] content)
    {
        // Search for " name=" ; also handle name= at very start (not valid =ybegin, but be safe).
        for (var i = 0; i + 5 < content.Length; i++)
        {
            if (content[i] == (byte)' ' &&
                content[i + 1] == (byte)'n' && content[i + 2] == (byte)'a' &&
                content[i + 3] == (byte)'m' && content[i + 4] == (byte)'e' && content[i + 5] == (byte)'=')
            {
                return i;
            }
        }

        return -1;
    }

    private static bool HasPartKeyword(List<byte[]> tokens)
    {
        foreach (var t in tokens)
        {
            if (t.AsSpan().StartsWith("part="u8))
            {
                return true;
            }
        }

        return false;
    }

    private static List<byte[]> SplitTokens(byte[] line)
    {
        var result = new List<byte[]>();
        var start = 0;
        for (var i = 0; i <= line.Length; i++)
        {
            if (i == line.Length || line[i] == (byte)' ' || line[i] == (byte)'\t')
            {
                if (i > start)
                {
                    result.Add(line[start..i]);
                }

                start = i + 1;
            }
        }

        return result;
    }

    private static Dictionary<string, byte[]> KeywordValues(List<byte[]> tokens)
    {
        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var token in tokens)
        {
            var eq = Array.IndexOf(token, (byte)'=');
            if (eq < 0)
            {
                continue;
            }

            var key = System.Text.Encoding.ASCII.GetString(token.AsSpan(0, eq));
            var value = token[(eq + 1)..];
            if (key is "part" or "size" or "begin" or "end")
            {
                if (values.TryGetValue(key, out var existing) && !existing.AsSpan().SequenceEqual(value))
                {
                    throw new YencEncryptionFailoverException($"Conflicting duplicate {key}= keywords");
                }
            }

            values[key] = value;
        }

        return values;
    }

    private static uint RequiredUInt(Dictionary<string, byte[]> values, string key, string lineName)
    {
        var v = ParseUIntToken(values.TryGetValue(key, out var raw) ? raw : null, $"{lineName} {key}=");
        if (v >= (1UL << 32))
        {
            throw new YencEncryptionFailoverException("SIZE_OVERFLOW: size or offset exceeds 4 GiB");
        }

        return (uint)v;
    }

    private static ulong ParseUIntToken(byte[]? raw, string what)
    {
        if (raw is null || raw.Length == 0)
        {
            throw new YencEncryptionFailoverException($"{what} lacks a valid parameter");
        }

        var s = System.Text.Encoding.ASCII.GetString(raw);
        if (!ulong.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var v))
        {
            throw new YencEncryptionFailoverException($"{what} lacks a valid parameter");
        }

        return v;
    }
}
