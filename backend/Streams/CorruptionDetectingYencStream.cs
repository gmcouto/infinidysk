using NzbWebDAV.Exceptions;
using Serilog;
using UsenetSharp.Encryption;
using UsenetSharp.Models;
using UsenetSharp.Streams;

namespace NzbWebDAV.Streams;

/// <summary>
/// Adds provider and segment context to decoded yEnc validation failures.
/// This is the lowest backend layer that sees decoded-body failures together
/// with segment/provider identity, so it also owns the INF-18 boundary
/// mapping (plan §4.6): Phase 1 provider-failover failures become
/// <see cref="UsenetCorruptArticleException"/>; Phase 1 local-fatal (KDF)
/// failures pass through untouched and are never classified as corruption.
/// </summary>
public sealed class CorruptionDetectingYencStream(
    YencStream inner,
    string segmentId,
    string providerKey) : YencStream(Null)
{
    private int _reported;

    public override async ValueTask<UsenetYencHeader?> GetYencHeadersAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await inner.GetYencHeadersAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException exception)
        {
            throw Map(exception);
        }
        catch (YencEncryptionFailoverException exception)
        {
            throw MapEncryptionFailure(exception);
        }
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException exception)
        {
            throw Map(exception);
        }
        catch (YencEncryptionFailoverException exception)
        {
            throw MapEncryptionFailure(exception);
        }
    }

    private UsenetCorruptArticleException MapEncryptionFailure(YencEncryptionFailoverException exception)
    {
        if (Interlocked.Exchange(ref _reported, 1) == 0)
        {
            ThrottledSegmentWarning.Write(
                $"{providerKey}\n{segmentId}",
                "Provider {Provider} returned an unauthenticated yEnc segment {SegmentId}. Reason: {Reason}",
                providerKey,
                segmentId,
                exception.Message);
            Log.Debug(
                exception,
                "yEnc authentication failure stack for provider {Provider} segment {SegmentId}",
                providerKey,
                segmentId);
        }

        return YencAuthenticationException.ToCorruptArticle(segmentId, providerKey, exception);
    }

    private UsenetCorruptArticleException Map(InvalidDataException exception)
    {
        if (Interlocked.Exchange(ref _reported, 1) == 0)
        {
            ThrottledSegmentWarning.Write(
                $"{providerKey}\n{segmentId}",
                "Provider {Provider} returned corrupt yEnc data for segment {SegmentId}. Reason: {Reason}",
                providerKey,
                segmentId,
                exception.Message);
            Log.Debug(
                exception,
                "Corrupt yEnc data stack for provider {Provider} segment {SegmentId}",
                providerKey,
                segmentId);
        }

        return new UsenetCorruptArticleException(segmentId, providerKey, exception);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            inner.Dispose();
        base.Dispose(disposing);
    }
}
