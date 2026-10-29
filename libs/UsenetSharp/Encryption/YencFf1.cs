namespace UsenetSharp.Encryption;

/// <summary>
/// Radix-253 FF1 control-line cipher (Control Standard v1.2 §2/§4).
/// Uses BouncyCastle <c>Org.BouncyCastle.Crypto.Fpe.FpeFf1Engine</c> over
/// <c>Org.BouncyCastle.Crypto.Engines.AesEngine</c> with the canonical
/// byte↔numeral bijection. INF-06 spike result: that engine reproduces the
/// vendored control-line vectors, so the plan §4.4 in-tree FF1 fallback
/// (over BCL Aes, mirroring SABnzbd encryption.py) was NOT needed.
/// </summary>
public static class YencFf1
{
    public const int Radix = 253;
    private const int MaxControlCiphertextBytes = 8192;

    public static byte ByteToNumeral(byte b) => b switch
    {
        >= 0x01 and <= 0x09 => (byte)(b - 1),
        0x0B => 9,
        0x0C => 10,
        >= 0x0E => (byte)(b - 3),
        _ => throw new YencEncryptionFailoverException($"Byte 0x{b:X2} is outside the 253-byte Alphabet"),
    };

    public static byte NumeralToByte(int i) => i switch
    {
        >= 0 and <= 8 => (byte)(i + 1),
        9 => 0x0B,
        10 => 0x0C,
        >= 11 and <= 252 => (byte)(i + 3),
        _ => throw new YencEncryptionFailoverException("Numeral out of range [0, 252]"),
    };

    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> tweak, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < 2)
        {
            throw new YencEncryptionFailoverException("LINE_TOO_SHORT: control line shorter than 2 bytes");
        }

        if (ciphertext.Length > MaxControlCiphertextBytes)
        {
            throw new YencEncryptionFailoverException("Control line ciphertext too large");
        }

        var numerals = new byte[ciphertext.Length];
        for (var i = 0; i < ciphertext.Length; i++)
        {
            numerals[i] = ByteToNumeral(ciphertext[i]);
        }

        var plainNumerals = Ff1EngineDecrypt(key, tweak, numerals);
        var result = new byte[plainNumerals.Length];
        for (var i = 0; i < plainNumerals.Length; i++)
        {
            result[i] = NumeralToByte(plainNumerals[i]);
        }

        return result;
    }

    private static byte[] Ff1EngineDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> tweak, byte[] numerals)
    {
        // BouncyCastle FpeFf1Engine/AesEngine path (INF-06 spike target).
        var engine = new Org.BouncyCastle.Crypto.Fpe.FpeFf1Engine(new Org.BouncyCastle.Crypto.Engines.AesEngine());
        var parameters = new Org.BouncyCastle.Crypto.Parameters.FpeParameters(
            new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key.ToArray()), Radix, tweak.ToArray());
        engine.Init(false, parameters);
        var output = new byte[numerals.Length];
        engine.ProcessBlock(numerals, 0, numerals.Length, output, 0);
        return output;
    }
}
