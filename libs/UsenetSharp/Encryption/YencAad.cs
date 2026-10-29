using System.Buffers.Binary;

namespace UsenetSharp.Encryption;

/// <summary>
/// AAD builder (Body Standard v1.2 §2.1): "yenc-body aad" || u32be(part) ||
/// u32be(begin) || u64be(segmentBytes) || u32be(nameLen) || nameBytes.
/// </summary>
public static class YencAad
{
    public static byte[] Build(ReadOnlySpan<byte> nameBytes, uint partNumber, uint partBegin, ulong segmentBytes)
    {
        if (nameBytes.IsEmpty)
        {
            throw new YencEncryptionFailoverException("MISSING_AAD_SUBJECT: =ybegin name parameter is required for AAD");
        }

        var aad = new byte[33 + nameBytes.Length];
        "yenc-body aad"u8.CopyTo(aad);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(13), partNumber);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(17), partBegin);
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(21), segmentBytes);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(29), (uint)nameBytes.Length);
        nameBytes.CopyTo(aad.AsSpan(33));
        return aad;
    }
}
