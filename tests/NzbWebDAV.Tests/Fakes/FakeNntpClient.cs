using System.Text;
using NzbWebDAV.Clients.Usenet;
using NzbWebDAV.Clients.Usenet.Contexts;
using NzbWebDAV.Clients.Usenet.Models;
using NzbWebDAV.Exceptions;
using NzbWebDAV.Models;
using NzbWebDAV.Streams;
using UsenetSharp.Models;
using UsenetSharp.Streams;
using RuntimeYencContext = UsenetSharp.Encryption.YencEncryptionContext;

namespace NzbWebDAV.Tests.Fakes;

internal sealed class FakeNntpClient(
    IReadOnlyDictionary<string, byte[]> segments,
    bool useCachedYencStreams = false,
    IReadOnlyDictionary<string, LongRange>? segmentRanges = null,
    Func<string, byte[], Stream>? decodedStreamFactory = null,
    IReadOnlyDictionary<string, byte[]>? localSegments = null,
    IReadOnlyDictionary<string, UsenetYencHeader>? yencHeaders = null,
    long? providerGeneration = 0,
    Func<string, int, Exception?>? headerProbeFailure = null,
    Func<string, int, UsenetYencHeader?>? responseHeaderFactory = null) : NntpClient
{
    // Copied at construction so tests can add/restore articles via Serve() without
    // mutating the caller's dictionary.
    private readonly Dictionary<string, byte[]> _segments = new(segments, StringComparer.Ordinal);
    private readonly IReadOnlyDictionary<string, byte[]> _localSegments =
        localSegments ?? new Dictionary<string, byte[]>(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _headerProbeAttempts = new(StringComparer.Ordinal);

    public int BatchRequestCount { get; private set; }
    public List<string[]> BatchSegmentIds { get; } = [];
    public int BodyRequestCount { get; private set; }
    public int HeaderProbeCount { get; private set; }
    public int CompletionCallbackCount { get; private set; }
    public int? LastPrewarmTarget { get; private set; }
    public Exception? PrewarmException { get; set; }
    public CancellationToken LastBatchToken { get; private set; }
    public TaskCompletionSource<int> FirstPrewarmRequested { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource FirstBatchRequested { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Dictionary<string, int> BodyRequestCounts { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, int> CompletionCallbackCounts { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, int> StatRequestCounts { get; } = new(StringComparer.Ordinal);
    public List<string> StatRequestOrder { get; } = [];
    public HashSet<string> RequestedSegmentIds { get; } = new(StringComparer.Ordinal);

    /// <summary>Adds or restores an article (e.g. provider-side recovery between checks).</summary>
    public void Serve(string segmentId, byte[] content) => _segments[segmentId] = content;

    // INF-19: raw encrypted wire articles served through the production
    // restore/decrypt path (UsenetSharp EncryptedYencAssembler via the
    // encrypted YencStream). Values are raw article bytes, never re-encoded.
    private readonly Dictionary<string, byte[]> _encryptedArticles = new(StringComparer.Ordinal);

    /// <summary>
    /// The runtime context encrypted articles are opened with. Settable so a
    /// test can correct the password and re-read the same article. When this
    /// is set it always wins (Phase 3 behaviour, unchanged). When it is null,
    /// see <see cref="UseAmbientEncryptionContext"/> for the ambient mode.
    /// </summary>
    public RuntimeYencContext? EncryptionContext { get; set; }

    /// <summary>
    /// Honest ambient mode (opt-in; default off so Phase 3 tests keep their
    /// fake-owned-context behaviour). When true AND
    /// <see cref="EncryptionContext"/> is null, <c>DecodedBodyAsync</c> reads
    /// <see cref="YencEncryptionRuntimeContext.CurrentRuntimeContext"/> at
    /// entry — exactly mirroring production <c>BaseNntpClient</c>, whose
    /// <c>YencEncryptionProvider</c> is
    /// <c>() =&gt; YencEncryptionRuntimeContext.CurrentRuntimeContext</c>.
    /// With no ambient runtime the fake then fails at body creation
    /// (fail-closed InvalidOperationException) instead of silently decrypting
    /// with a stashed context. This is what lets streaming tests see a
    /// missing Activate/Capture in production stream code: a candidate
    /// constructed without the captured runtime gets no decryption.
    /// </summary>
    public bool UseAmbientEncryptionContext { get; set; }

    /// <summary>
    /// The ambient runtime actually observed at each encrypted
    /// <c>DecodedBodyAsync</c> entry while in ambient mode (null = none) —
    /// the test-side observation of which mechanism presented the context.
    /// Lets stream tests pin that candidate/verified reads ran under exactly
    /// the captured runtime instance, not merely that bytes came out right.
    /// </summary>
    public List<RuntimeYencContext?> ObservedAmbientContexts { get; } = [];

    /// <summary>
    /// When true, the fake snapshots the ambient at <c>DecodedBodyAsync</c>
    /// entry and then suppresses the AsyncLocal flow while building the body
    /// — modelling a production provider whose work escapes the reader's
    /// logical flow. Only the entry snapshot may then decrypt; a caller that
    /// never captured/activated leaves a null snapshot and the body fails
    /// closed. The snapshot is evaluated eagerly at entry (context object
    /// only, no KDF). Default false; opt-in.
    /// </summary>
    public bool DetachEncryptedBodiesAfterEntry { get; set; }

    /// <summary>
    /// Registers a raw encrypted wire article. When <see cref="EncryptionContext"/>
    /// is set, bodies/headers for this id are produced by the production
    /// restore+AEAD transform; counters and completion counting are unchanged.
    /// </summary>
    public void ServeEncrypted(string segmentId, byte[] rawArticle) => _encryptedArticles[segmentId] = rawArticle;

    public bool IsEncrypted(string segmentId) => _encryptedArticles.ContainsKey(segmentId);

    /// <summary>
    /// When set, BODY responses claim this SegmentId instead of the requested one
    /// so tests can exercise mismatch rejection without a live NNTP scramble.
    /// </summary>
    public string? ForcedResponseSegmentId { get; set; }

    // B1/INF-25: controllable in-flight gate for encrypted bodies. When set,
    // the encrypted branch wraps the raw article in a stream that delivers
    // the first half, signals <see cref="EncryptedBodyInFlight"/>, then blocks
    // on this gate — mirroring EncryptedLoopbackTests' gated decode so a test
    // can cancel deterministically while a BODY is mid-flight. Honoured only
    // on the encrypted path; plain bodies keep using decodedStreamFactory.
    public TaskCompletionSource? EncryptedBodyGate { get; set; }

    /// <summary>Signalled once the first half of a gated encrypted body has been delivered.</summary>
    public TaskCompletionSource EncryptedBodyInFlight { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public override Task PrewarmConnectionsAsync(
        int targetConnections,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LastPrewarmTarget = targetConnections;
        FirstPrewarmRequested.TrySetResult(targetConnections);
        if (PrewarmException is not null)
            throw PrewarmException;
        return Task.CompletedTask;
    }

    public override Task ConnectAsync(
        string host, int port, bool useSsl, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public override Task<UsenetResponse> AuthenticateAsync(
        string user, string pass, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public override Task<UsenetStatResponse> StatAsync(
        SegmentId segmentId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = segmentId.ToString();
        StatRequestCounts[key] = StatRequestCounts.GetValueOrDefault(key) + 1;
        StatRequestOrder.Add(key);
        var exists = _segments.ContainsKey(key) || _encryptedArticles.ContainsKey(key);
        return Task.FromResult(new UsenetStatResponse
        {
            ResponseCode = exists
                ? (int)UsenetResponseType.ArticleExists
                : (int)UsenetResponseType.NoArticleWithThatMessageId,
            ResponseMessage = exists
                ? $"223 0 0 <{key}>"
                : $"430 No such article <{key}>",
            ArticleExists = exists,
        });
    }

    public override Task<UsenetHeadResponse> HeadAsync(
        SegmentId segmentId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public override Task<UsenetYencHeader> GetYencHeadersAsync(string segmentId, CancellationToken ct)
    {
        HeaderProbeCount++;
        var key = segmentId;
        var attempt = _headerProbeAttempts[key] = _headerProbeAttempts.GetValueOrDefault(key) + 1;
        if (headerProbeFailure?.Invoke(key, attempt) is { } failure)
            return Task.FromException<UsenetYencHeader>(failure);
        return base.GetYencHeadersAsync(segmentId, ct);
    }

    public override Task<UsenetDecodedBodyResponse> DecodedBodyAsync(
        SegmentId segmentId, CancellationToken cancellationToken) =>
        DecodedBodyAsync(segmentId, null, cancellationToken);

    public override Task<UsenetDecodedBodyResponse> DecodedBodyAsync(
        SegmentId segmentId,
        ArticleBodyCompletionHandler? onConnectionReadyAgain,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        BodyRequestCount++;
        var segmentKey = segmentId.ToString();
        RequestedSegmentIds.Add(segmentKey);
        BodyRequestCounts[segmentKey] = BodyRequestCounts.GetValueOrDefault(segmentKey) + 1;
        try
        {
            if (DetachEncryptedBodiesAfterEntry && EncryptionContext is null
                && _encryptedArticles.ContainsKey(segmentKey))
            {
                // Snapshot at entry (context object only — declaring Current
                // evaluates the Lazy runtime but no decode happens yet), then
                // create the body with THIS flow's AsyncLocal suppressed so
                // only the snapshot can decrypt. Restore immediately after.
                var snapshot = UseAmbientEncryptionContext
                    ? YencEncryptionRuntimeContext.CurrentRuntimeContext
                    : null;
                ObservedAmbientContexts.Add(snapshot);
                return DetachedEncryptedBody(segmentId, snapshot, onConnectionReadyAgain);
            }
            var response = CreateBodyResponse(segmentId);
            NoteCompletion(segmentKey);
            onConnectionReadyAgain?.Invoke(ArticleBodyResult.Retrieved);
            return Task.FromResult(response);
        }
        catch (Exception e)
        {
            // Return a faulted task so pipelined batch consumers can await
            // per-segment failures without aborting DecodedBodiesAsync itself.
            return Task.FromException<UsenetDecodedBodyResponse>(e);
        }
    }

    public override Task<UsenetDecodedBodyResponse?> TryGetLocalDecodedBodyAsync(
        SegmentId segmentId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = segmentId.ToString();
        return _localSegments.ContainsKey(key)
            ? Task.FromResult<UsenetDecodedBodyResponse?>(CreateBodyResponse(segmentId, _localSegments))
            : Task.FromResult<UsenetDecodedBodyResponse?>(null);
    }

    public override Task<UsenetDecodedBodyBatch> DecodedBodiesAsync(
        IReadOnlyList<SegmentId> segmentIds,
        ArticleBodyCompletionHandler? onConnectionReadyAgain,
        CancellationToken cancellationToken)
    {
        BatchRequestCount++;
        BatchSegmentIds.Add(segmentIds.Select(segmentId => segmentId.ToString()).ToArray());
        LastBatchToken = cancellationToken;
        FirstBatchRequested.TrySetResult();
        var responses = segmentIds
            .Select(segmentId => DecodedBodyAsync(segmentId, cancellationToken))
            .ToArray();
        onConnectionReadyAgain?.Invoke(ArticleBodyResult.Retrieved);
        return Task.FromResult(new UsenetDecodedBodyBatch { Responses = responses });
    }

    public override Task<UsenetDecodedArticleResponse> DecodedArticleAsync(
        SegmentId segmentId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public override Task<UsenetDecodedArticleResponse> DecodedArticleAsync(
        SegmentId segmentId,
        ArticleBodyCompletionHandler? onConnectionReadyAgain,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public override Task<UsenetDateResponse> DateAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public override Task<UsenetExclusiveConnection> AcquireExclusiveConnectionAsync(
        string segmentId, CancellationToken cancellationToken) =>
        Task.FromResult(new UsenetExclusiveConnection(null));

    public override Task<UsenetExclusiveConnection> AcquireExclusiveConnectionAsync(
        IReadOnlyList<SegmentId> segmentIds, CancellationToken cancellationToken) =>
        Task.FromResult(new UsenetExclusiveConnection(null));

    public override Task<UsenetDecodedBodyResponse> DecodedBodyAsync(
        SegmentId segmentId,
        UsenetExclusiveConnection exclusiveConnection,
        CancellationToken cancellationToken) =>
        DecodedBodyAsync(segmentId, exclusiveConnection.OnConnectionReadyAgain, cancellationToken);

    public override Task<UsenetDecodedBodyBatch> DecodedBodiesAsync(
        IReadOnlyList<SegmentId> segmentIds,
        UsenetExclusiveConnection exclusiveConnection,
        CancellationToken cancellationToken) =>
        DecodedBodiesAsync(
            segmentIds, exclusiveConnection.OnConnectionReadyAgain, cancellationToken);

    public override Task<UsenetDecodedArticleResponse> DecodedArticleAsync(
        SegmentId segmentId,
        UsenetExclusiveConnection exclusiveConnection,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public override void Dispose()
    {
    }

    private void NoteCompletion(string segmentKey)
    {
        CompletionCallbackCount++;
        CompletionCallbackCounts[segmentKey] = CompletionCallbackCounts.GetValueOrDefault(segmentKey) + 1;
    }

    private Task<UsenetDecodedBodyResponse> DetachedEncryptedBody(
        SegmentId segmentId,
        RuntimeYencContext? snapshot,
        ArticleBodyCompletionHandler? onConnectionReadyAgain)
    {
        // Evaluated outside the caller's logical flow so no ambient leaks in.
        // The entry snapshot is re-presented explicitly, mirroring production
        // providers that snapshot the runtime once per operation.
        try
        {
            UsenetDecodedBodyResponse response;
            using (ExecutionContext.SuppressFlow())
            {
                using var activate = YencEncryptionRuntimeContext.Activate(snapshot);
                response = CreateBodyResponse(segmentId, detachedSnapshot: snapshot);
            }
            NoteCompletion(segmentId.ToString());
            onConnectionReadyAgain?.Invoke(ArticleBodyResult.Retrieved);
            return Task.FromResult(response);
        }
        catch (Exception e)
        {
            return Task.FromException<UsenetDecodedBodyResponse>(e);
        }
    }

    private UsenetDecodedBodyResponse CreateBodyResponse(SegmentId segmentId) =>
        CreateBodyResponse(segmentId, _segments);

    private UsenetDecodedBodyResponse CreateBodyResponse(
        SegmentId segmentId,
        RuntimeYencContext? detachedSnapshot) =>
        CreateBodyResponse(segmentId, _segments, detachedSnapshot);

    private UsenetDecodedBodyResponse CreateBodyResponse(
        SegmentId segmentId,
        IReadOnlyDictionary<string, byte[]> segments,
        RuntimeYencContext? detachedSnapshot = null)
    {
        var key = segmentId.ToString();
        if (_encryptedArticles.TryGetValue(key, out var rawArticle))
        {
            // Explicit fake-owned context wins (Phase 3). Detached mode uses
            // its explicit snapshot; ambient mode mirrors BaseNntpClient by
            // snapshotting the AsyncLocal ambient at body entry.
            RuntimeYencContext? context;
            if (detachedSnapshot is not null || DetachEncryptedBodiesAfterEntry)
            {
                context = EncryptionContext ?? detachedSnapshot;
            }
            else
            {
                context = EncryptionContext
                    ?? (UseAmbientEncryptionContext
                        ? YencEncryptionRuntimeContext.CurrentRuntimeContext
                        : null);
                if (UseAmbientEncryptionContext && EncryptionContext is null)
                    ObservedAmbientContexts.Add(context);
            }
            if (context is null)
                throw new InvalidOperationException(
                    "FakeNntpClient: set EncryptionContext before serving encrypted articles, " +
                    "or enable UseAmbientEncryptionContext inside an active scope.");
            Stream raw = new MemoryStream(rawArticle, writable: false);
            // decodedStreamFactory (plain-path hook) is honoured here too when
            // it can wrap the raw bytes; the deterministic gate below is the
            // smallest mechanism when a test needs mid-flight control.
            if (decodedStreamFactory is not null)
                raw = decodedStreamFactory(key, rawArticle);
            else if (EncryptedBodyGate is { } gate)
                raw = new GatedRawArticleStream(rawArticle, EncryptedBodyInFlight, gate);
            return new UsenetDecodedBodyResponse
            {
                SegmentId = ForcedResponseSegmentId ?? key,
                ResponseCode = (int)UsenetResponseType.ArticleRetrievedBodyFollows,
                ResponseMessage = "222 fake encrypted body",
                Stream = new YencStream(raw, context),
            };
        }

        if (!segments.TryGetValue(key, out var bytes))
            throw new UsenetArticleNotFoundException(key, "430 No such article")
            {
                ProviderGeneration = providerGeneration,
            };
        var range = default(LongRange);
        var hasRange = segmentRanges is not null && segmentRanges.TryGetValue(key, out range);
        var scriptedHeader = responseHeaderFactory?.Invoke(key, BodyRequestCounts.GetValueOrDefault(key));
        var header = scriptedHeader
            ?? (yencHeaders is not null && yencHeaders.TryGetValue(key, out var exactHeader)
                ? exactHeader
                : new UsenetYencHeader
                {
                    FileName = "fake.bin",
                    FileSize = segmentRanges is { Count: > 0 }
                        ? segmentRanges.Values.Max(value => value.EndExclusive)
                        : bytes.Length,
                    LineLength = 128,
                    PartNumber = 1,
                    TotalParts = segments.Count,
                    PartOffset = hasRange ? range!.StartInclusive : 0,
                    PartSize = hasRange ? range!.Count : bytes.Length,
                });

        YencStream stream = useCachedYencStreams
            ? new CachedYencStream(
                header,
                decodedStreamFactory?.Invoke(key, bytes)
                    ?? new MemoryStream(bytes, writable: false))
            : new YencStream(new MemoryStream(EncodeYenc(bytes), writable: false));
        return new UsenetDecodedBodyResponse
        {
            SegmentId = ForcedResponseSegmentId ?? key,
            ResponseCode = (int)UsenetResponseType.ArticleRetrievedBodyFollows,
            ResponseMessage = "222 fake body",
            Stream = stream,
        };
    }

    /// <summary>
    /// Raw-article stream that delivers the first half, signals in-flight,
    /// then blocks on the release gate (cancellation-aware). The encrypted
    /// YencStream buffers the whole article before opening, so blocking here
    /// blocks the decode mid-flight with zero plaintext released.
    /// </summary>
    private sealed class GatedRawArticleStream(
        byte[] article, TaskCompletionSource inFlight, TaskCompletionSource release) : Stream
    {
        private int _position;
        private bool _signalled;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var half = article.Length / 2;
            if (_position < half)
            {
                var count = Math.Min(buffer.Length, half - _position);
                article.AsSpan(_position, count).CopyTo(buffer.Span);
                _position += count;
                if (_position >= half && !_signalled)
                {
                    _signalled = true;
                    inFlight.TrySetResult();
                }
                return count;
            }

            if (_position < article.Length)
            {
                await release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                var count = Math.Min(buffer.Length, article.Length - _position);
                article.AsSpan(_position, count).CopyTo(buffer.Span);
                _position += count;
                return count;
            }

            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static byte[] EncodeYenc(ReadOnlySpan<byte> source)
    {
        using var output = new MemoryStream(source.Length + 128);
        WriteAscii(output, $"=ybegin line=128 size={source.Length} name=fake.bin\r\n");
        var lineLength = 0;
        foreach (var value in source)
        {
            var encoded = unchecked((byte)(value + 42));
            if (encoded is 0 or (byte)'\n' or (byte)'\r' or (byte)'=')
            {
                output.WriteByte((byte)'=');
                output.WriteByte(unchecked((byte)(encoded + 64)));
                lineLength += 2;
            }
            else
            {
                output.WriteByte(encoded);
                lineLength++;
            }

            if (lineLength < 128) continue;
            WriteAscii(output, "\r\n");
            lineLength = 0;
        }

        if (lineLength > 0) WriteAscii(output, "\r\n");
        WriteAscii(output, $"=yend size={source.Length}\r\n");
        return output.ToArray();
    }

    private static void WriteAscii(Stream output, string value) =>
        output.Write(Encoding.ASCII.GetBytes(value));
}
