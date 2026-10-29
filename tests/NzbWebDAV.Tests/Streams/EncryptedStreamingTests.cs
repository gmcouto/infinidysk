using NzbWebDAV.Clients.Usenet.Contexts;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Exceptions;
using NzbWebDAV.Models;
using NzbWebDAV.Streams;
using NzbWebDAV.Tests.Fakes;
using NzbWebDAV.Tests.TestUtils;
using UsenetSharp.Encryption;
using RuntimeContext = UsenetSharp.Encryption.YencEncryptionContext;

namespace NzbWebDAV.Tests.Streams;

/// <summary>
/// Phase 4 (INF-21..25): encrypted streaming proof. Articles come from the
/// INF-05 vendored fixtures (authoring-time Python reference; no C# test
/// encrypts with production code). The fake serves them through the
/// production <c>YencStream</c> restore+AEAD path and counts per-segment
/// BODY requests. Stream construction mirrors the WebDAV path: persisted
/// blob fields -&gt; <see cref="YencEncryptionRuntimeContext.BeginForFile"/>
/// scope -&gt; stream, with the scope disposed before reads.
/// </summary>
[Collection(nameof(GlobalLoggerCollection))]
public sealed class EncryptedStreamingTests
{
    private const string Password = "public-conformance-vector-key-2026";
    private const string P1 = "enc-p1@example.com";
    private const string P2 = "enc-p2@example.com";
    // 256 + 244: the two multipart parts of file-b.bin (manifest segmentIndex 2,3).
    private static readonly LongRange[] MultipartRanges = [new(0, 256), new(256, 500)];

    private static string FixtureDir => Path.Join(
        AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles");

    private static byte[] Load(string name) => File.ReadAllBytes(Path.Join(FixtureDir, name));

    private static FakeNntpClient MultipartFake(
        byte[]? part2Override = null, string password = Password, string[][]? fallbacks = null)
    {
        var fake = new FakeNntpClient(
            new Dictionary<string, byte[]>(),
            segmentRanges: new Dictionary<string, LongRange> { [P1] = MultipartRanges[0], [P2] = MultipartRanges[1] });
        fake.EncryptionContext = new RuntimeContext(password);
        fake.ServeEncrypted(P1, Load("article-part1.bin"));
        fake.ServeEncrypted(P2, part2Override ?? Load("article-part2.bin"));
        return fake;
    }

    /// <summary>
    /// Builds an NzbFileStream exactly the way DatabaseStoreNzbFile does:
    /// persisted DavNzbFile fields -> BeginForFile scope -> GetFileStream,
    /// then the scope ends. Reads must still decrypt via the captured context.
    /// </summary>
    private static NzbFileStream BuildWebDavStyleStream(
        FakeNntpClient client, DavNzbFile blob, long fileSize, LongRange[]? ranges)
    {
        using var scope = YencEncryptionRuntimeContext.BeginForFile(
            blob.YencEncrypted, blob.YencTransportPassword);
        return client.GetFileStream(
            blob.SegmentIds, fileSize, articleBufferSize: 4, segmentByteRanges: ranges,
            segmentFallbacks: null, streamingBodyBatchWidth: 4);
    }

    private static DavNzbFile MultipartBlob(string? password = Password, bool encrypted = true) => new()
    {
        Id = Guid.NewGuid(),
        SegmentIds = [P1, P2],
        YencEncrypted = encrypted ? true : null,
        YencTransportPassword = password,
    };

    private static async Task<byte[]> ReadAllAsync(Stream stream)
    {
        await using (stream)
        {
            using var output = new MemoryStream();
            await stream.CopyToAsync(output);
            return output.ToArray();
        }
    }

    private static bool ContainsAuthFailure(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is YencEncryptionFailoverException) return true;
            if (current is UsenetCorruptArticleException &&
                YencAuthenticationException.IsAuthenticationFailure(current)) return true;
            if (YencAuthenticationException.IsAuthenticationFailure(current)) return true;
        }
        return false;
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken ct = default)
    {
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) break;
            read += n;
        }
        return buffer[..read];
    }

    private static byte[] TamperCiphertext(byte[] article)
    {
        // Flip one byte inside a middle data line (mirrors the Phase 3 helper).
        var copy = article.ToArray();
        var lines = new List<int>();
        for (var i = 0; i < copy.Length; i++)
            if (copy[i] == (byte)'\n') lines.Add(i + 1);
        copy[lines[2] + 10] ^= 0x01;
        return copy;
    }

    // ---------- INF-21: persistence-agnostic wiring ----------

    [Fact]
    public void EncryptedBlob_WithoutPassword_FailsClosedAtConstruction()
    {
        var blob = MultipartBlob(password: null);
        var client = MultipartFake();
        var error = Assert.Throws<YencEncryptionLocalException>(() =>
            BuildWebDavStyleStream(client, blob, 500, MultipartRanges));
        Assert.Contains("MISSING_PASSWORD", error.Message);
        Assert.Equal(0, client.BodyRequestCount);
    }

    [Fact]
    public async Task OrdinaryBlob_NoScope_IdenticalPlainRead()
    {
        // Ordinary (unencrypted) blob + no ambient scope: upstream path.
        var content1 = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        var content2 = Enumerable.Range(0, 244).Select(i => (byte)(255 - i)).ToArray();
        var client = new FakeNntpClient(
            new Dictionary<string, byte[]> { [P1] = content1, [P2] = content2 },
            segmentRanges: new Dictionary<string, LongRange> { [P1] = MultipartRanges[0], [P2] = MultipartRanges[1] });
        Assert.Null(YencEncryptionRuntimeContext.CurrentRuntimeContext);
        var stream = client.GetFileStream(
            new[] { P1, P2 }, 500, articleBufferSize: 4, segmentByteRanges: MultipartRanges,
            streamingBodyBatchWidth: 4);
        Assert.Null(YencEncryptionRuntimeContext.CurrentRuntimeContext);
        Assert.Equal(content1.Concat(content2).ToArray(), await ReadAllAsync(stream));
    }

    [Fact]
    public async Task DavMultipartFileStream_EncryptedMeta_ReadsPlaintext_AfterConstructionScopeEnds()
    {
        var client = MultipartFake();
        var mpf = new DavMultipartFile
        {
            Id = Guid.NewGuid(),
            Metadata = new DavMultipartFile.Meta
            {
                YencEncrypted = true,
                YencTransportPassword = Password,
                FileParts =
                [
                    new DavMultipartFile.FilePart
                    {
                        SegmentIds = [P1, P2],
                        SegmentIdByteRange = new LongRange(0, 500),
                        FilePartByteRange = new LongRange(0, 500),
                        SegmentByteRanges = MultipartRanges,
                        SegmentByteRangesTrusted = true,
                    },
                ],
            },
        };
        // Constructor captures from Meta and fails closed; no ambient scope here at all.
        await using var stream = new DavMultipartFileStream(
            mpf, client, articleBufferSize: 4, resolver: null, usePipelinedBodyRequests: true);
        Assert.Equal(Load("expected-multipart.bin"), await ReadAllAsync(stream));
    }

    [Fact]
    public void DavMultipartFileStream_EncryptedWithoutPassword_FailsClosed()
    {
        var client = MultipartFake();
        var mpf = new DavMultipartFile
        {
            Id = Guid.NewGuid(),
            Metadata = new DavMultipartFile.Meta
            {
                YencEncrypted = true,
                YencTransportPassword = null,
                FileParts = [],
            },
        };
        Assert.Throws<YencEncryptionLocalException>(() => new DavMultipartFileStream(
            mpf, client, articleBufferSize: 4, resolver: null, usePipelinedBodyRequests: true));
    }

    // ---------- INF-23: sequential streaming ----------

    [Fact]
    public async Task Sequential_NzbFileStream_ReturnsExactPlaintextInOrder()
    {
        var client = MultipartFake();
        var stream = BuildWebDavStyleStream(client, MultipartBlob(), 500, MultipartRanges);
        Assert.Equal(Load("expected-multipart.bin"), await ReadAllAsync(stream));
        Assert.Equal(1, client.BodyRequestCounts[P1]);
        Assert.Equal(1, client.BodyRequestCounts[P2]);
    }

    [Fact]
    public async Task Sequential_MultiSegmentStreamDirect_ReturnsExactPlaintext()
    {
        var client = MultipartFake();
        using var scope = YencEncryptionRuntimeContext.Begin(Password);
        var stream = MultiSegmentStream.Create(
            new[] { P1, P2 }.AsMemory(), client, articleBufferSize: 4,
            estimatedSegmentSize: 256, failFastOnFirstSegment: true,
            usePipelinedBodyRequests: false, CancellationToken.None,
            fileName: "file-b.bin",
            exactSegmentSizes: new long[] { 256, 244 });
        Assert.Equal(Load("expected-multipart.bin"), await ReadAllAsync(stream));
    }

    [Fact]
    public async Task WrongPassword_StreamErrors_ZeroBytesDelivered()
    {
        var client = MultipartFake(password: "wrong-password");
        var blob = MultipartBlob(password: "wrong-password");
        var stream = BuildWebDavStyleStream(client, blob, 500, MultipartRanges);
        await using (stream)
        {
            using var output = new MemoryStream();
            await Assert.ThrowsAnyAsync<Exception>(async () => await stream.CopyToAsync(output));
            Assert.Equal(0, output.Length);
        }
    }

    [Fact]
    public async Task TamperedMiddleSegment_OnlyPrecedingPlaintextDelivered_FailoverTier()
    {
        // File A: single-part (global segmentIndex 1). File B: two parts
        // (segmentIndex 2,3) — B's first segment carries a LATER global index
        // than A's only segment (INF-23d fixture layout, manifest.json).
        var client = new FakeNntpClient(new Dictionary<string, byte[]>());
        client.EncryptionContext = new RuntimeContext(Password);
        client.ServeEncrypted("enc-single@example.com", Load("article-single.bin"));
        client.ServeEncrypted(P1, Load("article-part1.bin"));
        client.ServeEncrypted(P2, TamperCiphertext(Load("article-part2.bin")));

        var blobA = new DavNzbFile
        {
            Id = Guid.NewGuid(), SegmentIds = ["enc-single@example.com"],
            YencEncrypted = true, YencTransportPassword = Password,
        };
        var streamA = BuildWebDavStyleStream(client, blobA, 328, [new LongRange(0, 328)]);
        Assert.Equal(Load("expected-single.bin"), await ReadAllAsync(streamA));

        // B's tail segment tampered: read delivers B's first part exactly,
        // then fails — no byte of the tampered segment is released.
        var streamB = BuildWebDavStyleStream(client, MultipartBlob(), 500, MultipartRanges);
        await using (streamB)
        {
            using var output = new MemoryStream();
            var error = await Assert.ThrowsAnyAsync<Exception>(
                async () => await streamB.CopyToAsync(output));
            Assert.Equal(Load("expected-multipart.bin")[..256], output.ToArray());
            // Retry/fallback attempted first: the tampered segment was
            // re-fetched at least once after its first authentication failure
            // before the read failed terminally (INF-23c).
            Assert.True(client.BodyRequestCounts[P2] >= 2,
                $"expected retries on {P2}, got {client.BodyRequestCounts.GetValueOrDefault(P2)}");
            // The terminal error wraps the authentication failure: the fake
            // surfaces the raw failover tier, MultiSegmentStream retries it as
            // corruption and exhausts into TransientSegmentExhaustionException;
            // the production pump maps the same failure to
            // UsenetCorruptArticleException first (Phase 3 boundary tests).
            Assert.True(ContainsAuthFailure(error),
                $"unexpected error type: {error.GetType().FullName}: {error.Message}");
        }
    }

    // ---------- INF-24: seeks ----------

    [Fact]
    public async Task Seek_MidSegment_ReturnsExactSlice_FetchesOnlyCoveringSegments()
    {
        var client = MultipartFake();
        var stream = BuildWebDavStyleStream(client, MultipartBlob(), 500, MultipartRanges);
        await using (stream)
        {
            stream.Seek(300, SeekOrigin.Begin);
            var slice = await ReadExactlyAsync(stream, 100);
            Assert.Equal(Load("expected-multipart.bin")[300..400], slice);
            Assert.Equal(0, client.BodyRequestCounts.GetValueOrDefault(P1));
            Assert.True(client.BodyRequestCounts.GetValueOrDefault(P2) >= 1);
        }
    }

    [Fact]
    public async Task Seek_AcrossBoundary_AndIntoLastSegment_ExactSlices()
    {
        var client = MultipartFake();
        var stream = BuildWebDavStyleStream(client, MultipartBlob(), 500, MultipartRanges);
        await using (stream)
        {
            // Mid first segment.
            stream.Seek(100, SeekOrigin.Begin);
            Assert.Equal(Load("expected-multipart.bin")[100..150],
                await ReadExactlyAsync(stream, 50));

            // Across the 256 boundary.
            stream.Seek(250, SeekOrigin.Begin);
            Assert.Equal(Load("expected-multipart.bin")[250..270],
                await ReadExactlyAsync(stream, 20));

            // Into the last segment near EOF.
            stream.Seek(490, SeekOrigin.Begin);
            Assert.Equal(Load("expected-multipart.bin")[490..500],
                await ReadExactlyAsync(stream, 10));
        }
    }

    [Fact]
    public async Task Seek_IntoTamperedSegment_ZeroBytesForRange()
    {
        var client = MultipartFake(part2Override: TamperCiphertext(Load("article-part2.bin")));
        var stream = BuildWebDavStyleStream(client, MultipartBlob(), 500, MultipartRanges);
        await using (stream)
        {
            stream.Seek(300, SeekOrigin.Begin);
            using var output = new MemoryStream();
            await Assert.ThrowsAnyAsync<Exception>(async () => await stream.CopyToAsync(output));
            Assert.Equal(0, output.Length);
        }
    }

    [Fact]
    public async Task GeometryDisagreement_ShortRanges_AuthenticatedGeometryGoverns()
    {
        // Plan §4.5 (F4 pin): authenticated geometry governs for this
        // consumer. Short declared ranges (246/234 vs authenticated 256/244)
        // fail ValidateAndCloneSegmentByteRanges end-check (480 != Length
        // 500), so NzbFileStream discards them and sizes segments from the
        // authenticated headers; the read then delivers the FULL
        // authenticated plaintext (500 bytes), not the declared 480 prefix
        // and not an error. Exactly one branch is pinned — no catch-all.
        var client = MultipartFake();
        var shortRanges = new LongRange[] { new(0, 246), new(246, 480) };
        var stream = BuildWebDavStyleStream(client, MultipartBlob(), 500, shortRanges);
        await using (stream)
        {
            Assert.Equal(Load("expected-multipart.bin"), await ReadAllAsync(stream));
        }
    }

    // ---------- INF-25: bounded memory + lifecycle ----------

    [Fact]
    public async Task Seek_LastSegment_NeverFetchesEarlierSegments()
    {
        var client = MultipartFake();
        var stream = BuildWebDavStyleStream(client, MultipartBlob(), 500, MultipartRanges);
        await using (stream)
        {
            stream.Seek(400, SeekOrigin.Begin);
            Assert.Equal(Load("expected-multipart.bin")[400..450],
                await ReadExactlyAsync(stream, 50));
            Assert.Equal(0, client.BodyRequestCounts.GetValueOrDefault(P1));
            Assert.Equal(0, client.StatRequestCounts.GetValueOrDefault(P1));
        }
    }

    [Fact]
    public async Task PreCancelled_Read_DeliversZeroBytes()
    {
        // Pre-cancelled only (renamed from the misleading "MidRead"): the
        // token is cancelled before any BODY is issued, so no completion
        // callback can exist — the mid-flight exactly-once pin lives in
        // Cancellation_MidFlight below.
        var client = MultipartFake();
        var blob = new DavNzbFile
        {
            Id = Guid.NewGuid(), SegmentIds = ["enc-single@example.com"],
            YencEncrypted = true, YencTransportPassword = Password,
        };
        var stream = BuildWebDavStyleStream(client, blob, 328, [new LongRange(0, 328)]);
        await using (stream)
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            using var output = new MemoryStream();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await stream.CopyToAsync(output, cts.Token));
            Assert.Equal(0, output.Length);
        }
        Assert.Empty(client.CompletionCallbackCounts);
    }

    [Fact]
    public async Task Cancellation_MidFlight_DeliversZeroBytes_CallbackExactlyOnce()
    {
        // B1/INF-25: deterministic mid-flight cancellation at the streaming
        // layer, mirroring EncryptedLoopbackTests' gated decode. The fake's
        // encrypted-body gate delivers half the raw article, signals
        // in-flight, then blocks; the test cancels while that BODY is blocked
        // inside the encrypted YencStream's buffering read, then releases.
        var client = new FakeNntpClient(new Dictionary<string, byte[]>());
        // Ambient mode (no fake-owned context): decryption only happens while
        // production code presents the captured runtime, exactly like the
        // verified-proof pin — a regression in Activate would surface here too.
        client.UseAmbientEncryptionContext = true;
        Assert.Null(client.EncryptionContext);
        client.ServeEncrypted("enc-single@example.com", Load("article-single.bin"));
        client.EncryptedBodyGate = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var blob = new DavNzbFile
        {
            Id = Guid.NewGuid(), SegmentIds = ["enc-single@example.com"],
            YencEncrypted = true, YencTransportPassword = Password,
        };
        var stream = BuildWebDavStyleStream(client, blob, 328, [new LongRange(0, 328)]);
        await using (stream)
        {
            using var cts = new CancellationTokenSource();
            using var output = new MemoryStream();
            var copy = stream.CopyToAsync(output, cts.Token);
            // First BODY is now blocked in flight inside the decode.
            await client.EncryptedBodyInFlight.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cts.Cancel();
            client.EncryptedBodyGate.TrySetResult();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await copy);
            Assert.Equal(0, output.Length);
        }
        // Non-vacuous: the dictionary must contain the in-flight segment, and
        // its completion callback must have fired exactly once.
        Assert.NotEmpty(client.CompletionCallbackCounts);
        Assert.Equal(1, client.CompletionCallbackCounts["enc-single@example.com"]);
    }

    // ---------- B3/INF-21: encrypted + PAR2 verification proof ----------

    [Fact]
    public async Task EncryptedWithVerificationProof_StreamsExactPlaintext()
    {
        // B3: an encrypted DavNzbFile carrying a Par2FileProof routes reads
        // through Par2VerifiedFileStream, whose candidate NzbFileStreams are
        // constructed lazily (sequential producer / recovery). Before the fix
        // ReadAsync entered VerifiedStream BEFORE Activate(_encryptionRuntime)
        // and candidates captured the ambient (disposed) scope — i.e. null —
        // so this read could never decrypt. The proof is built over the
        // expected plaintext exactly as Par2VerifiedFileStreamTests.CreateProof
        // does, so PAR2 verifies the decrypted bytes.
        //
        // Honesty of this pin (corrected after trace): the fake runs in
        // UseAmbientEncryptionContext mode with NO fake-owned
        // EncryptionContext. Like production BaseNntpClient, it can only
        // decrypt when production code presents the ambient runtime at
        // DecodedBodyAsync entry. On today's production code the sequential
        // producer's candidates receive that runtime from the candidate
        // constructors themselves (NzbFileStream.cs OpenSequentialPar2Candidate
        // :166 and ReadPar2CandidateAsync :186 re-Activate the captured
        // runtime before `new NzbFileStream`), plus AsyncLocal flows through
        // the producer's Task.Yield continuation — NOT from outer ReadAsync's
        // Activate, whose using-dispose exits before the producer is even
        // lazily created (VerifiedStream is first touched at ReadAsync:229,
        // after the disposed Activate's construction flow ended; a sync
        // `using var` in an async method restores the AsyncLocal as soon as
        // that method's synchronous execution completes). The outer-ordering
        // mutation therefore (correctly) does NOT break this test — claiming
        // otherwise would be vacuous. The production reorder at ReadAsync:227
        // is retained as an explicit guarantee for the direct/pre candidate
        // path, and the mechanism this test actually pins is asserted
        // instance-level in CandidateReads_RunUnderCapturedRuntime below.
        var expected = Load("expected-single.bin");
        var proof = Par2VerifiedFileStreamTests.CreateProof(expected, 128);
        var client = new FakeNntpClient(new Dictionary<string, byte[]>());
        client.UseAmbientEncryptionContext = true;
        Assert.Null(client.EncryptionContext);
        client.ServeEncrypted("enc-single@example.com", Load("article-single.bin"));

        NzbFileStream stream;
        using (var scope = YencEncryptionRuntimeContext.BeginForFile(true, Password))
        {
            stream = client.GetFileStream(
                ["enc-single@example.com"], expected.Length, articleBufferSize: 4,
                segmentByteRanges: [new LongRange(0, expected.Length)],
                segmentFallbacks: null, streamingBodyBatchWidth: 4,
                verificationProof: proof);
        }
        // Scope disposed at return (WebDAV shape): reads must re-enter the
        // runtime the outer stream captured, and candidates must capture it too.
        await using (stream)
        {
            Assert.Equal(expected, await ReadAllAsync(stream));
            Assert.True(client.BodyRequestCounts.GetValueOrDefault("enc-single@example.com") >= 1);
        }
    }

    [Fact]
    public async Task CandidateReads_RunUnderCapturedRuntime()
    {
        // Mechanism pin (instance-level): every encrypted body the verified
        // path fetched was presented to the decode under the SAME runtime
        // instance the outer stream captured (the Begin scope's runtime —
        // Capture() returns that instance, and lazy construction stores it;
        // candidates re-Activate exactly it). If candidate construction ever
        // stopped carrying the captured runtime, the fake would observe null
        // (or a different instance) and — ambient mode being fail-closed —
        // the read would fail instead of silently decrypting.
        var expected = Load("expected-single.bin");
        var proof = Par2VerifiedFileStreamTests.CreateProof(expected, 128);
        var client = new FakeNntpClient(new Dictionary<string, byte[]>());
        client.UseAmbientEncryptionContext = true;
        client.ServeEncrypted("enc-single@example.com", Load("article-single.bin"));

        RuntimeContext? captured;
        NzbFileStream stream;
        using (var scope = YencEncryptionRuntimeContext.BeginForFile(true, Password))
        {
            captured = YencEncryptionRuntimeContext.CurrentRuntimeContext;
            Assert.NotNull(captured);
            stream = client.GetFileStream(
                ["enc-single@example.com"], expected.Length, articleBufferSize: 4,
                segmentByteRanges: [new LongRange(0, expected.Length)],
                segmentFallbacks: null, streamingBodyBatchWidth: 4,
                verificationProof: proof);
        }
        Assert.Null(YencEncryptionRuntimeContext.CurrentRuntimeContext);
        await using (stream)
        {
            Assert.Equal(expected, await ReadAllAsync(stream));
        }
        Assert.NotEmpty(client.ObservedAmbientContexts);
        Assert.All(client.ObservedAmbientContexts, observed =>
            Assert.Same(captured, observed));
    }

    [Fact]
    public async Task CandidateReads_DetachedFlow_OnlyCapturedSnapshotDecrypts()
    {
        // Sensitivity proof for the pinned mechanism: with
        // DetachEncryptedBodiesAfterEntry the fake suppresses AsyncLocal
        // flow after DecodedBodyAsync entry, so AsyncLocal propagation can
        // no longer mask a missing capture — only an explicitly presented
        // snapshot decrypts. Sequential candidates still succeed because
        // OpenSequentialPar2Candidate/ReadPar2CandidateAsync re-Activate the
        // captured runtime BEFORE constructing the candidate (its own
        // _encryptionRuntime snapshot then presents per read). Control in
        // CandidateCaptureControl_DetachedWithoutCapture_FailsClosed proves
        // the detached fake is fail-closed when nothing was captured.
        var expected = Load("expected-single.bin");
        var proof = Par2VerifiedFileStreamTests.CreateProof(expected, 128);
        var client = new FakeNntpClient(new Dictionary<string, byte[]>());
        client.UseAmbientEncryptionContext = true;
        client.DetachEncryptedBodiesAfterEntry = true;
        client.ServeEncrypted("enc-single@example.com", Load("article-single.bin"));

        NzbFileStream stream;
        using (var scope = YencEncryptionRuntimeContext.BeginForFile(true, Password))
        {
            stream = client.GetFileStream(
                ["enc-single@example.com"], expected.Length, articleBufferSize: 4,
                segmentByteRanges: [new LongRange(0, expected.Length)],
                segmentFallbacks: null, streamingBodyBatchWidth: 4,
                verificationProof: proof);
        }
        await using (stream)
        {
            Assert.Equal(expected, await ReadAllAsync(stream));
            Assert.NotEmpty(client.ObservedAmbientContexts);
            Assert.All(client.ObservedAmbientContexts, observed =>
                Assert.NotNull(observed));
        }
    }

    [Fact]
    public async Task CandidateCaptureControl_DetachedWithoutCapture_FailsClosed()
    {
        // Control for CandidateReads_DetachedFlow_OnlyCapturedSnapshotDecrypts:
        // detach the fake and give the outer stream NO captured runtime
        // (constructed outside any scope — ordinary-file construction shape
        // over an encrypted article). The verified read must fail closed
        // (zero verified bytes / error), never decrypt from a leftover
        // ambient. This is the condition the sequential-candidate path would
        // be in if candidate construction stopped carrying the capture.
        var expected = Load("expected-single.bin");
        var proof = Par2VerifiedFileStreamTests.CreateProof(expected, 128);
        var client = new FakeNntpClient(new Dictionary<string, byte[]>());
        client.UseAmbientEncryptionContext = true;
        client.DetachEncryptedBodiesAfterEntry = true;
        client.ServeEncrypted("enc-single@example.com", Load("article-single.bin"));

        Assert.Null(YencEncryptionRuntimeContext.CurrentRuntimeContext);
        await using var stream = client.GetFileStream(
            ["enc-single@example.com"], expected.Length, articleBufferSize: 4,
            segmentByteRanges: [new LongRange(0, expected.Length)],
            segmentFallbacks: null, streamingBodyBatchWidth: 4,
            verificationProof: proof);
        using var output = new MemoryStream();
        await Assert.ThrowsAnyAsync<Exception>(async () => await stream.CopyToAsync(output));
        Assert.Equal(0, output.Length);
        Assert.Contains(null, client.ObservedAmbientContexts);
    }
}
