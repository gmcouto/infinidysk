using NzbWebDAV.Clients.Usenet;
using NzbWebDAV.Clients.Usenet.Contexts;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Exceptions;
using NzbWebDAV.Queue;
using NzbWebDAV.Services.Repair;
using NzbWebDAV.Streams;
using NzbWebDAV.Tests.Fakes;
using UsenetSharp.Encryption;
using UsenetSharp.Models;
using UsenetSharp.Streams;
using BackendContext = NzbWebDAV.Queue.YencEncryptionContext;
using RuntimeContext = UsenetSharp.Encryption.YencEncryptionContext;

namespace NzbWebDAV.Tests.Streams;

/// <summary>
/// Phase 3 (INF-14/16/17/18/19/20): encrypted articles served by the
/// INF-19 fake through the production restore/decrypt path, backend
/// boundary mapping, and cache bypasses under an ambient context.
/// </summary>
public sealed class EncryptedYencPhase3Tests
{
    private const string Password = "public-conformance-vector-key-2026";
    private const string SegmentId = "enc-single@example.com";

    private static string FixtureDir => Path.Join(
        AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles");

    private static byte[] Load(string name) => File.ReadAllBytes(Path.Join(FixtureDir, name));

    private static FakeNntpClient EncryptedFake(string password = Password)
    {
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        fake.EncryptionContext = new RuntimeContext(password);
        fake.ServeEncrypted(SegmentId, Load("article-single.bin"));
        return fake;
    }

    private static async Task<byte[]> ReadAllAsync(YencStream stream)
    {
        await using (stream)
        {
            using var output = new MemoryStream();
            await stream.CopyToAsync(output);
            return output.ToArray();
        }
    }

    // ---------- INF-19 + INF-20 through the fake ----------

    [Fact]
    public async Task EncryptedFake_CorrectPassword_ExactPlaintext_CountersPreserved()
    {
        var fake = EncryptedFake();
        var response = await fake.DecodedBodyAsync(SegmentId, CancellationToken.None);
        Assert.Equal(Load("expected-single.bin"), await ReadAllAsync(response.Stream!));
        Assert.Equal(1, fake.BodyRequestCount);
        Assert.Equal(1, fake.BodyRequestCounts[SegmentId]);
        Assert.Equal(1, fake.CompletionCallbackCounts.GetValueOrDefault(SegmentId));
        var header = await fake.GetYencHeadersAsync(SegmentId, CancellationToken.None);
        Assert.Equal(328, header.PartSize);
        Assert.Equal(1, fake.HeaderProbeCount);
    }

    [Fact]
    public async Task EncryptedFake_Multipart_PartsAssembleToExpectedFile()
    {
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        fake.EncryptionContext = new RuntimeContext(Password);
        fake.ServeEncrypted("enc-p1@example.com", Load("article-part1.bin"));
        fake.ServeEncrypted("enc-p2@example.com", Load("article-part2.bin"));

        var p1 = await fake.DecodedBodyAsync("enc-p1@example.com", CancellationToken.None);
        var p2 = await fake.DecodedBodyAsync("enc-p2@example.com", CancellationToken.None);
        var bytes = (await ReadAllAsync(p1.Stream!)).Concat(await ReadAllAsync(p2.Stream!)).ToArray();
        Assert.Equal(Load("expected-multipart.bin"), bytes);
    }

    [Fact]
    public async Task EncryptedFake_WrongPassword_ZeroBytes_FailoverTier()
    {
        var fake = EncryptedFake("wrong-password");
        var response = await fake.DecodedBodyAsync(SegmentId, CancellationToken.None);
        await using var stream = response.Stream!;
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<YencEncryptionFailoverException>(
            async () => await stream.CopyToAsync(output));
        Assert.Equal(0, output.Length);
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(
            new YencEncryptionFailoverException("x")));
    }

    [Theory]
    // ciphertext: byte flip inside a data line (wire CRC / AEAD must reject).
    [InlineData("tamper-ciphertext")]
    // tag / salt / index: parsed-field tampers from the vendored fixture set
    // (tamper-tag.bin flips one tag byte with salt/index in agreement;
    // tamper-dual-*.bin pin the salt/index disagreement) — see manifest.json.
    [InlineData("tamper-tag")]
    [InlineData("tamper-salt")]
    [InlineData("tamper-index")]
    public async Task EncryptedFake_TamperedArticle_ZeroBytes_FailoverTier(string kind)
    {
        var article = kind switch
        {
            "tamper-ciphertext" => Tamper(Load("article-single.bin"), kind),
            "tamper-tag" => Load("tamper-tag.bin"),
            "tamper-salt" => Load("tamper-dual-salt.bin"),
            "tamper-index" => Load("tamper-dual-index.bin"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
        };
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        fake.EncryptionContext = new RuntimeContext(Password);
        fake.ServeEncrypted(SegmentId, article);

        var response = await fake.DecodedBodyAsync(SegmentId, CancellationToken.None);
        await using var stream = response.Stream!;
        using var output = new MemoryStream();
        // F3(a): the thrown exception must BE the failover tier (the type the
        // backend boundary maps to UsenetCorruptArticleException — see
        // BoundaryMapping_FailoverBecomesCorruptArticle_WithAuthMarker), not
        // merely "any exception", and it must be an authentication failure.
        var error = await Assert.ThrowsAsync<YencEncryptionFailoverException>(
            async () => await stream.CopyToAsync(output));
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(error));
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public async Task EncryptedFake_TruncatedArticle_ZeroBytes()
    {
        var article = Load("article-single.bin");
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        fake.EncryptionContext = new RuntimeContext(Password);
        fake.ServeEncrypted(SegmentId, article[..(article.Length / 2)]);

        var response = await fake.DecodedBodyAsync(SegmentId, CancellationToken.None);
        await using var stream = response.Stream!;
        using var output = new MemoryStream();
        await Assert.ThrowsAnyAsync<Exception>(async () => await stream.CopyToAsync(output));
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public async Task OrdinaryFake_ThroughNewPath_ByteIdentical()
    {
        var content = Enumerable.Range(0, 300).Select(i => (byte)(i * 7)).ToArray();
        var fake = new FakeNntpClient(new Dictionary<string, byte[]> { ["plain@example.com"] = content });
        var response = await fake.DecodedBodyAsync("plain@example.com", CancellationToken.None);
        Assert.Equal(content, await ReadAllAsync(response.Stream!));
    }

    // ---------- INF-18 backend boundary mapping ----------

    [Fact]
    public void BoundaryMapping_FailoverBecomesCorruptArticle_WithAuthMarker()
    {
        var failover = new YencEncryptionFailoverException("AUTHENTICATION_FAILURE");
        var mapped = YencAuthenticationException.ToCorruptArticle(SegmentId, "provider-a", failover);
        Assert.IsType<UsenetCorruptArticleException>(mapped);
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(mapped));
        Assert.IsType<YencAuthenticationException>(mapped.InnerException);
    }

    [Fact]
    public void BoundaryMapping_LocalFatalNeverBecomesCorruptArticle()
    {
        var local = new YencEncryptionLocalException("Argon2id key derivation failed");
        Assert.Throws<ArgumentException>(
            () => YencAuthenticationException.ToCorruptArticle(SegmentId, "provider-a", local));
        Assert.False(YencAuthenticationException.IsAuthenticationFailure(local));
    }

    [Fact]
    public async Task CorruptionDetectingStream_MapsFailover_AndPassesLocalFatalThrough()
    {
        var failoverStream = new CorruptionDetectingYencStream(
            new YencStream(new MemoryStream(Load("article-single.bin"), writable: false),
                new RuntimeContext("wrong-password")),
            SegmentId, "provider-a");
        var mapped = await Assert.ThrowsAsync<UsenetCorruptArticleException>(
            async () => await failoverStream.ReadAsync(new byte[64]));
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(mapped));

        // A failover from the raw stream stays failover-tier here too (the
        // local-fatal pass-through is pinned by BoundaryMapping_* above:
        // ToCorruptArticle refuses local types outright).
        var failing = new YencStream(
            new MemoryStream(Load("article-single.bin"), writable: false),
            new RuntimeContext("wrong-password"));
        await Assert.ThrowsAsync<YencEncryptionFailoverException>(
            async () => await failing.ReadAsync(new byte[64]));
    }

    // ---------- INF-16/17: YencStream ciphertext-cache parity ----------

    [Fact]
    public async Task YencStream_CiphertextBytes_ReauthenticateOnEveryRead()
    {
        var ciphertextArticle = Load("article-single.bin");
        var first = await ReadAllAsync(new YencStream(
            new MemoryStream(ciphertextArticle, writable: false), new RuntimeContext(Password)));
        Assert.Equal(Load("expected-single.bin"), first);

        // Same stored bytes under a wrong password must fail — caches hold
        // ciphertext only, never authenticated plaintext.
        var stream = new YencStream(
            new MemoryStream(ciphertextArticle, writable: false), new RuntimeContext("wrong-password"));
        await using (stream)
        {
            using var output = new MemoryStream();
            await Assert.ThrowsAsync<YencEncryptionFailoverException>(
                async () => await stream.CopyToAsync(output));
            Assert.Equal(0, output.Length);
        }
    }

    // ---------- INF-17 cache bypass counters ----------

    [Fact]
    public async Task SegmentCache_UnderContext_BypassesReadAndWrite_SecondReadRefetches()
    {
        var cacheDir = NewTempDir();
        const string id = "enc-cache@example.com";
        var content = "live-plain-segment"u8.ToArray();
        try
        {
            var inner = new FakeNntpClient(
                new Dictionary<string, byte[]> { [id] = content }, useCachedYencStreams: true);
            using var client = new SegmentCacheNntpClient(inner, cacheDir, maxBytes: 1024 * 1024);
            await client.CatalogLoadTask.WaitAsync(TimeSpan.FromSeconds(5));

            using (YencEncryptionRuntimeContext.Begin(Password))
            {
                var first = await client.DecodedBodyAsync(id, CancellationToken.None);
                Assert.Equal(content, await ReadAllAsync(first.Stream!));
                var second = await client.DecodedBodyAsync(id, CancellationToken.None);
                Assert.Equal(content, await ReadAllAsync(second.Stream!));
                Assert.Equal(2, inner.BodyRequestCount);
                Assert.Null(await client.TryGetLocalDecodedBodyAsync(id, CancellationToken.None));
            }

            // Without a context the cache works normally again.
            var third = await client.DecodedBodyAsync(id, CancellationToken.None);
            Assert.Equal(content, await ReadAllAsync(third.Stream!));
        }
        finally
        {
            DeleteDir(cacheDir);
        }
    }

    [Fact]
    public async Task SegmentCache_PreSeededCiphertext_NeverServedUnderContext()
    {
        var cacheDir = NewTempDir();
        try
        {
            // Pre-seed with the ciphertext article bytes as if a buggy writer
            // had cached them; under a context they must never be served.
            WriteSegmentCacheEntry(cacheDir, SegmentId, Load("article-single.bin"));
            var inner = EncryptedFake();
            using var client = new SegmentCacheNntpClient(inner, cacheDir, maxBytes: 1024 * 1024);
            await client.CatalogLoadTask.WaitAsync(TimeSpan.FromSeconds(5));

            using (YencEncryptionRuntimeContext.Begin(Password))
            {
                var response = await client.DecodedBodyAsync(SegmentId, CancellationToken.None);
                Assert.Equal(Load("expected-single.bin"), await ReadAllAsync(response.Stream!));
                Assert.Equal(1, inner.BodyRequestCount);
            }
        }
        finally
        {
            DeleteDir(cacheDir);
        }
    }

    [Fact]
    public async Task ArticleCache_UnderContext_BypassesLocalBodies()
    {
        var content = "article-cache-content"u8.ToArray();
        var inner = new FakeNntpClient(new Dictionary<string, byte[]> { ["ac@example.com"] = content });
        using var client = new ArticleCachingNntpClient(inner);

        var first = await client.DecodedBodyAsync("ac@example.com", CancellationToken.None);
        Assert.Equal(content, await ReadAllAsync(first.Stream!));
        var cached = await client.DecodedBodyAsync("ac@example.com", CancellationToken.None);
        Assert.Equal(content, await ReadAllAsync(cached.Stream!));
        Assert.Equal(1, inner.BodyRequestCount);

        using (YencEncryptionRuntimeContext.Begin(Password))
        {
            var bypassed = await client.DecodedBodyAsync("ac@example.com", CancellationToken.None);
            Assert.Equal(content, await ReadAllAsync(bypassed.Stream!));
            Assert.Equal(2, inner.BodyRequestCount);
        }
    }

    [Fact]
    public async Task RepairedPatch_UnderContext_BypassesLocalBody()
    {
        var dir = NewTempDir();
        const string id = "patched-enc@example.com";
        var patched = "repaired!"u8.ToArray();
        var live = "live!"u8.ToArray();
        try
        {
            var store = new RepairPatchStore(dir, 1024 * 1024);
            await store.EnsureCatalogLoadedAsync(CancellationToken.None);
            store.CommitPatch(id, patched, new UsenetYencHeader
            {
                FileName = "fake.bin",
                FileSize = patched.Length,
                LineLength = 128,
                PartNumber = 1,
                TotalParts = 1,
                PartSize = patched.Length,
                PartOffset = 0,
            });
            var inner = new FakeNntpClient(new Dictionary<string, byte[]> { [id] = live });
            using var client = new RepairedSegmentNntpClient(inner, store);

            var local = await client.DecodedBodyAsync(id, CancellationToken.None);
            Assert.Equal(patched, await ReadAllAsync(local.Stream!));
            Assert.Equal(0, inner.BodyRequestCount);

            using (YencEncryptionRuntimeContext.Begin(Password))
            {
                var remote = await client.DecodedBodyAsync(id, CancellationToken.None);
                Assert.Equal(live, await ReadAllAsync(remote.Stream!));
                Assert.Equal(1, inner.BodyRequestCount);
                Assert.Null(await client.TryGetLocalDecodedBodyAsync(id, CancellationToken.None));
            }
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public async Task HeaderCache_FailedAuthentication_CachesNothing()
    {
        var inner = EncryptedFake("wrong-password");
        using var client = new HeaderCachingNntpClient(inner);

        using (YencEncryptionRuntimeContext.Begin("wrong-password"))
        {
            await Assert.ThrowsAsync<YencEncryptionFailoverException>(
                async () => await client.GetYencHeadersAsync(SegmentId, CancellationToken.None));
            await Assert.ThrowsAsync<YencEncryptionFailoverException>(
                async () => await client.GetYencHeadersAsync(SegmentId, CancellationToken.None));
            // Each probe re-fetched (nothing cached after failure).
            Assert.Equal(2, inner.HeaderProbeCount);
        }

        inner.EncryptionContext = new RuntimeContext(Password);
        using (YencEncryptionRuntimeContext.Begin(Password))
        {
            var header = await client.GetYencHeadersAsync(SegmentId, CancellationToken.None);
            Assert.Equal(328, header.PartSize);
            var again = await client.GetYencHeadersAsync(SegmentId, CancellationToken.None);
            Assert.Equal(328, again.PartSize);
        }
    }

    [Fact]
    public async Task HeaderCache_TamperedTag_CachesNothing_RepeatedProbeRefetches()
    {
        // F1 regression, backend layer: correct password but tampered tag.
        // Before the F1 fix the pump published restored headers before the
        // AEAD open, so this probe returned (and HeaderCachingNntpClient
        // cached) unauthenticated geometry. Now it must throw the failover
        // tier and every repeated probe must re-fetch.
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        fake.EncryptionContext = new RuntimeContext(Password);
        fake.ServeEncrypted(SegmentId, Load("tamper-tag.bin"));
        using var client = new HeaderCachingNntpClient(fake);

        using (YencEncryptionRuntimeContext.Begin(Password))
        {
            await Assert.ThrowsAsync<YencEncryptionFailoverException>(
                async () => await client.GetYencHeadersAsync(SegmentId, CancellationToken.None));
            await Assert.ThrowsAsync<YencEncryptionFailoverException>(
                async () => await client.GetYencHeadersAsync(SegmentId, CancellationToken.None));
            Assert.Equal(2, fake.HeaderProbeCount);
        }
    }

    // ---------- INF-14 ambient flow ----------

    [Fact]
    public void AmbientContext_NoneWithoutScope_AndRestoresAfterDispose()
    {
        Assert.Null(YencEncryptionRuntimeContext.CurrentRuntimeContext);
        using (YencEncryptionRuntimeContext.Begin(Password))
        {
            Assert.NotNull(YencEncryptionRuntimeContext.CurrentRuntimeContext);
            Assert.True(YencEncryptionRuntimeContext.IsActive);
        }

        Assert.Null(YencEncryptionRuntimeContext.CurrentRuntimeContext);
        Assert.False(YencEncryptionRuntimeContext.IsActive);
    }

    [Fact]
    public void BackendContext_ToRuntimeContext_OnlyWhenEncrypted()
    {
        Assert.Null(BackendContext.None.ToRuntimeContext());
        Assert.NotNull(new BackendContext(true, Password).ToRuntimeContext());
    }

    // ---------- tamper helpers (byte edits of vendored articles only) ----------

    private static byte[] Tamper(byte[] article, string kind)
    {
        var result = article.ToArray();
        var lines = SplitLines(result);
        switch (kind)
        {
            case "tamper-ciphertext":
                // Flip one byte inside a middle data line (line index 2).
                // Parsed-field tag/salt/index tampers are NOT done here: they
                // live inside the FF1-encrypted =yencryption line, so flipping
                // bytes there garbles the whole line rather than tampering a
                // parsed field. Those cases use the vendored fixtures instead
                // (tamper-tag.bin, tamper-dual-salt.bin, tamper-dual-index.bin).
                result = Flip(result, lines[2].Start + 10);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind), kind, null);
        }

        return result;
    }

    private static byte[] Flip(byte[] source, int offset)
    {
        var copy = source.ToArray();
        copy[offset] ^= 0x01;
        return copy;
    }

    private static List<(int Start, int Length)> SplitLines(byte[] bytes)
    {
        var lines = new List<(int, int)>();
        var start = 0;
        for (var i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] != (byte)'\n') continue;
            lines.Add((start, i - start + 1));
            start = i + 1;
        }

        if (start < bytes.Length)
            lines.Add((start, bytes.Length - start));
        return lines;
    }

    private static string NewTempDir()
    {
        var dir = Path.Join(Path.GetTempPath(), "phase3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void DeleteDir(string dir)
    {
        try
        {
            Directory.Delete(dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort temp cleanup.
        }
    }

    private static void WriteSegmentCacheEntry(string cacheDir, string segmentId, byte[] content)
    {
        var hash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(segmentId)));
        var directory = Path.Join(cacheDir, hash[..2]);
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Join(directory, hash), content);
        var header = new UsenetYencHeader
        {
            FileName = "file-a.bin",
            FileSize = content.Length,
            LineLength = 128,
            PartNumber = 1,
            PartOffset = 0,
            PartSize = content.Length,
            TotalParts = 1,
            HasTotalParts = false,
        };
        File.WriteAllText(
            Path.Join(directory, hash) + ".h",
            System.Text.Json.JsonSerializer.Serialize(header, SegmentCacheNntpClient.HeaderJsonOptions));
    }
}
