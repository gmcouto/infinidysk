using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace UsenetSharp.Encryption;

/// <summary>
/// XChaCha20-Poly1305 open (Body §4/§5). The 16-byte tag travels in
/// <c>=yencryption</c>, not the body. Failure releases zero plaintext.
/// Uses BouncyCastle <see cref="XChaCha20Poly1305"/> (24-byte nonce).
/// </summary>
public static class YencBodyCipher
{
    public static byte[] Open(
        ReadOnlySpan<byte> masterKey,
        uint segmentIndex,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> aad)
    {
        if (tag.Length != 16)
        {
            throw new YencEncryptionFailoverException("INVALID_TAG_LENGTH: tag must be 16 bytes");
        }

        if (aad.IsEmpty)
        {
            throw new YencEncryptionFailoverException("AUTHENTICATION_FAILURE: empty AAD is invalid");
        }

        var nonce = YencKeySchedule.DeriveBodyNonce(masterKey, segmentIndex);
        var cipher = new XChaCha20Poly1305();
        var parameters = new AeadParameters(new KeyParameter(masterKey.ToArray()), 128, nonce, aad.ToArray());
        cipher.Init(false, parameters);
        var combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));
        var output = new byte[cipher.GetOutputSize(combined.Length)];
        try
        {
            var written = cipher.ProcessBytes(combined, 0, combined.Length, output, 0);
            written += cipher.DoFinal(output, written);
            return output[..written];
        }
        catch (Exception ex)
        {
            // Zero-output: never return partial plaintext.
            throw new YencEncryptionFailoverException("AUTHENTICATION_FAILURE: Poly1305 authentication failed", ex);
        }
    }
}
