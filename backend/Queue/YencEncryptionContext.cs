using NzbWebDAV.Exceptions;

namespace NzbWebDAV.Queue;

/// <summary>
/// Immutable per-NZB yEnc transport-encryption context (plan §4.1/§4.2, Body §8):
/// whether the NZB is encrypted and, if so, the resolved transport password.
/// Kept separate from the archive password so downstream archive handling keeps
/// today's semantics. The password is never logged. Derived keys live only in
/// the Phase 1 UsenetSharp runtime cache, never here.
/// </summary>
public sealed record YencEncryptionContext(bool Encrypted, string? TransportPassword)
{
    public static YencEncryptionContext None { get; } = new(false, null);

    /// <summary>
    /// Builds the context from NZB head metadata plus the filename password.
    /// Marker reading (Body §8 / other clients): <c>yenc_encrypted</c> trimmed,
    /// ASCII case-insensitive "true" enables encryption; any other/missing value
    /// is an ordinary NZB. When encrypted, <c>yenc_version</c> must equal "1.2"
    /// exactly after trim and <c>yenc_cipher</c> must equal "XChaCha20-Poly1305"
    /// ASCII case-insensitively after trim (either may be absent; present-but-empty
    /// fails). Transport password = filename password ?? NZB meta password.
    /// </summary>
    /// <exception cref="NonRetryableDownloadException">
    /// Invalid version/cipher or missing/empty transport password — fail closed
    /// at ingest, before any article fetch (plan §4.6 local-fatal tier).
    /// </exception>
    public static YencEncryptionContext FromMetadata(
        IReadOnlyDictionary<string, string> metadata, string? filenamePassword)
    {
        var encrypted = metadata.TryGetValue("yenc_encrypted", out var marker)
            && string.Equals(marker?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
        if (!encrypted)
            return None;

        ValidateMarkerMetadata(metadata);

        var transportPassword = filenamePassword
            ?? (metadata.TryGetValue("password", out var metaPassword) ? metaPassword : null);
        if (string.IsNullOrEmpty(transportPassword))
        {
            throw new NonRetryableDownloadException(
                "Encrypted NZB has no transport password: no password could be resolved " +
                "from the filename or NZB metadata.");
        }

        return new YencEncryptionContext(true, transportPassword);
    }

    private static void ValidateMarkerMetadata(IReadOnlyDictionary<string, string> metadata)
    {
        if (metadata.TryGetValue("yenc_version", out var version)
            && !string.Equals(version?.Trim(), "1.2", StringComparison.Ordinal))
        {
            throw new NonRetryableDownloadException(
                "Encrypted NZB declares an unsupported yenc_version; expected 1.2.");
        }

        if (metadata.TryGetValue("yenc_cipher", out var cipher)
            && !string.Equals(cipher?.Trim(), "XChaCha20-Poly1305", StringComparison.OrdinalIgnoreCase))
        {
            throw new NonRetryableDownloadException(
                "Encrypted NZB declares an unsupported yenc_cipher; expected XChaCha20-Poly1305.");
        }
    }
}

/// <summary>
/// Bridges the backend context to the Phase 1 UsenetSharp runtime context
/// (single-flight master-key cache). Null when unencrypted. Not process-global:
/// callers own the returned instance per job/stream (Phase 3 wires it in).
/// </summary>
public static class YencEncryptionContextExtensions
{
    public static UsenetSharp.Encryption.YencEncryptionContext? ToRuntimeContext(
        this YencEncryptionContext context) =>
        context is { Encrypted: true, TransportPassword: { Length: > 0 } password }
            ? new UsenetSharp.Encryption.YencEncryptionContext(password)
            : null;
}
