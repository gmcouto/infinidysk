namespace NzbWebDAV.Exceptions;

/// <summary>
/// Marker for a yEnc authentication failure (wrong password or tampered article
/// bytes) — the Phase 1 provider-failover tier (plan §4.6). Phase 3's decoder
/// wiring wraps Phase 1 failover errors in this type / carries it as an inner
/// exception of <see cref="UsenetCorruptArticleException"/> so persistence
/// classifiers can distinguish "the password may be wrong" from evidence that
/// the provider copy itself is corrupt.
/// </summary>
/// <remarks>
/// An authentication failure is NOT evidence about the provider copy once the
/// password itself may be wrong, so it must never be persisted as
/// <see cref="NzbWebDAV.Database.Models.DavNzbFile.CorruptSegmentIndices"/> or
/// <see cref="NzbWebDAV.Database.Models.DavNzbFile.MissingSegmentIndices"/>
/// (INF-13): a corrected password must make the file readable again with no
/// persistent marks. Use <see cref="IsAuthenticationFailure"/> at every
/// classification point that would otherwise record corrupt/missing marks.
/// </remarks>
public sealed class YencAuthenticationException(string segmentId, Exception? innerException = null)
    : Exception(
        $"yEnc authentication failed for segment {segmentId}.",
        innerException)
{
    public string SegmentId { get; } = segmentId;

    /// <summary>
    /// Backend-boundary mapping (INF-18, plan §4.6): a Phase 1 provider-
    /// failover failure surfacing from a decoded-body stream becomes a
    /// <see cref="UsenetCorruptArticleException"/> so existing corruption
    /// retries, fallback Message-IDs and provider failover consume it, with
    /// this marker preserved as the inner exception so
    /// <see cref="IsAuthenticationFailure"/> keeps distinguishing "the
    /// password may be wrong" from provider-copy evidence. A Phase 1
    /// local-fatal (KDF) failure is never mapped: it must stay the distinct
    /// local type and abort, never retry as provider corruption.
    /// </summary>
    public static UsenetCorruptArticleException ToCorruptArticle(
        string segmentId, string providerKey, Exception failoverException)
    {
        ArgumentNullException.ThrowIfNull(failoverException);
        if (failoverException is UsenetSharp.Encryption.YencEncryptionLocalException)
        {
            throw new ArgumentException(
                "Local-fatal encryption failures must never be mapped to provider corruption.",
                nameof(failoverException));
        }

        return new UsenetCorruptArticleException(
            segmentId, providerKey, new YencAuthenticationException(segmentId, failoverException));
    }

    /// <summary>
    /// True when <paramref name="exception"/> (or any inner exception) is an
    /// authentication failure: this marker type, or a Phase 1
    /// <see cref="UsenetSharp.Encryption.YencEncryptionFailoverException"/>.
    /// </summary>
    public static bool IsAuthenticationFailure(Exception? exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is YencAuthenticationException
                or UsenetSharp.Encryption.YencEncryptionFailoverException)
                return true;
        }

        return false;
    }
}
