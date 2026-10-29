using UsenetSharp.Clients;
using UsenetSharp.Encryption;
using UsenetSharp.Models;
using UsenetSharpTest.Support;

namespace UsenetSharpTest.Encryption;

/// <summary>
/// INF-14/18/20 through the real <see cref="UsenetClient"/>: the options
/// provider is snapshotted per operation on a pooled client, completion
/// callbacks fire exactly once (success / failure / cancellation), and
/// pipelined batches stay in request order.
/// </summary>
[TestFixture]
public class EncryptedLoopbackTests
{
    private const string Password = "public-conformance-vector-key-2026";

    // Vendored inside this test project (see TestFixtures/EncryptedArticles/README.md).
    private static string FixtureDir => Path.Join(
        AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles");

    private static byte[] Load(string name) => File.ReadAllBytes(Path.Join(FixtureDir, name));

    private static Task<ScriptedNntpServer> StartServerAsync(
        IReadOnlyDictionary<string, byte[]> articles) =>
        Task.FromResult(new ScriptedNntpServer(async (command, writer, cancellationToken) =>
        {
            var id = command["BODY <".Length..^1];
            await writer.WriteLineAsync("222 body follows");
            await writer.FlushAsync();
            await writer.BaseStream.WriteAsync(articles[id], cancellationToken);
            await writer.WriteLineAsync(".");
            await writer.FlushAsync();
        }));

    [Test]
    public async Task DecodedBodyAsync_CorrectPassword_Plaintext_AndCallbackOnce()
    {
        var articles = new Dictionary<string, byte[]> { ["enc-1@example.com"] = Load("article-single.bin") };
        await using var server = await StartServerAsync(articles);
        var context = new YencEncryptionContext(Password);
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () => context,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        var outcomes = new List<ArticleBodyResult>();
        var response = await client.DecodedBodyAsync(
            new SegmentId("enc-1@example.com"), (result, _) => outcomes.Add(result), CancellationToken.None);
        await using var stream = response.Stream!;
        var headers = await stream.GetYencHeadersAsync();
        using var output = new MemoryStream();
        await stream.CopyToAsync(output);

        Assert.That(output.ToArray(), Is.EqualTo(Load("expected-single.bin")));
        Assert.That(headers!.PartSize, Is.EqualTo(328));
        Assert.That(outcomes, Is.EqualTo(new[] { ArticleBodyResult.Retrieved }));
    }

    [Test]
    public async Task DecodedBodyAsync_WrongPassword_ZeroBytes_Failover_CallbackNotRetrieved()
    {
        var articles = new Dictionary<string, byte[]> { ["enc-1@example.com"] = Load("article-single.bin") };
        await using var server = await StartServerAsync(articles);
        var context = new YencEncryptionContext("wrong-password");
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () => context,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        var outcomes = new List<ArticleBodyResult>();
        var response = await client.DecodedBodyAsync(
            new SegmentId("enc-1@example.com"), (result, _) => outcomes.Add(result), CancellationToken.None);
        await using var stream = response.Stream!;
        using var output = new MemoryStream();
        var error = Assert.CatchAsync(async () => await stream.CopyToAsync(output));
        // Background pump may surface the failure on read completion; either
        // way zero bytes are delivered and the callback fires exactly once.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (outcomes.Count == 0 && DateTime.UtcNow < deadline)
            await Task.Delay(25);

        Assert.That(output.Length, Is.EqualTo(0));
        Assert.That(outcomes.Count, Is.EqualTo(1));
        Assert.That(outcomes[0], Is.EqualTo(ArticleBodyResult.NotRetrieved));
        _ = error;
    }

    [Test]
    public async Task DecodedBodiesAsync_EncryptedBatch_InRequestOrder_CallbackOnce()
    {
        var articles = new Dictionary<string, byte[]>
        {
            ["enc-1@example.com"] = Load("article-single.bin"),
            ["enc-2@example.com"] = Load("article-part1.bin"),
            ["enc-3@example.com"] = Load("article-part2.bin"),
        };
        await using var server = await StartServerAsync(articles);
        var context = new YencEncryptionContext(Password);
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            MaxPipelineDepth = 8,
            YencEncryptionProvider = () => context,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        var outcomes = new List<ArticleBodyResult>();
        var ids = articles.Keys.Select(id => new SegmentId(id)).ToArray();
        var batch = await client.DecodedBodiesAsync(
            ids, (result, _) => outcomes.Add(result), CancellationToken.None);

        var expectedMultipart = Load("expected-multipart.bin");
        var expected = new[]
        {
            Load("expected-single.bin"), expectedMultipart[..256], expectedMultipart[256..],
        };
        for (var i = 0; i < ids.Length; i++)
        {
            var response = await batch.Responses[i];
            Assert.That(response.SegmentId.ToString(), Is.EqualTo(ids[i].ToString()));
            await using var stream = response.Stream!;
            using var output = new MemoryStream();
            await stream.CopyToAsync(output);
            Assert.That(output.ToArray(), Is.EqualTo(expected[i]), $"response {i}");
        }

        await batch.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.That(outcomes, Is.EqualTo(new[] { ArticleBodyResult.Retrieved }));
    }

    [Test]
    public async Task DecodedBodyAsync_CancelledMidFlight_ZeroBytes_CallbackCancelledExactlyOnce()
    {
        // F2: deterministic in-flight cancellation. The loopback server sends
        // only the first half of the encrypted article, signals that, then
        // waits on a gate; the test cancels while the pump is blocked reading
        // the remainder, then releases the gate so the drain can complete.
        // No timing sleep is the synchronisation mechanism.
        var article = Load("article-single.bin");
        var half = article.Length / 2;
        var firstHalfSent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRest = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new ScriptedNntpServer(async (command, writer, cancellationToken) =>
        {
            var id = command["BODY <".Length..^1];
            await writer.WriteLineAsync("222 body follows");
            await writer.FlushAsync();
            await writer.BaseStream.WriteAsync(article.AsMemory(0, half), cancellationToken);
            await writer.BaseStream.FlushAsync(cancellationToken);
            firstHalfSent.SetResult();
            await releaseRest.Task.WaitAsync(cancellationToken);
            await writer.BaseStream.WriteAsync(article.AsMemory(half), cancellationToken);
            await writer.WriteLineAsync(".");
            await writer.FlushAsync();
        });
        var context = new YencEncryptionContext(Password);
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () => context,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        using var cts = new CancellationTokenSource();
        var outcomes = new List<ArticleBodyResult>();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = await client.DecodedBodyAsync(
            new SegmentId("enc-1@example.com"),
            (result, _) => { outcomes.Add(result); completion.TrySetResult(); },
            cts.Token);
        await using var stream = response.Stream!;
        using var output = new MemoryStream();
        var copyTask = stream.CopyToAsync(output, cts.Token);

        // The pump is now blocked mid-article: cancel during the transfer.
        await firstHalfSent.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cts.Cancel();
        releaseRest.SetResult();

        await Assert.CatchAsync(async () => await copyTask);
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));

        // Encrypted path releases nothing before authentication, and the
        // drain-clean cancellation maps to Cancelled (upstream semantic in
        // ReadDecodedBodyToPipeAsync), exactly once.
        Assert.That(output.Length, Is.EqualTo(0));
        Assert.That(outcomes, Is.EqualTo(new[] { ArticleBodyResult.Cancelled }));
    }

    [Test]
    public async Task DecodedBodyAsync_PreCancelled_Throws_CallbackNotRetrievedExactlyOnce()
    {
        // Kept separate because the semantics differ from mid-flight: a token
        // cancelled before the operation starts faults at the command-lock
        // wait, which upstream maps to NotRetrieved (BodyAsync.cs catch).
        var articles = new Dictionary<string, byte[]> { ["enc-1@example.com"] = Load("article-single.bin") };
        await using var server = await StartServerAsync(articles);
        var context = new YencEncryptionContext(Password);
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () => context,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var outcomes = new List<ArticleBodyResult>();
        await Assert.CatchAsync(async () => await client.DecodedBodyAsync(
            new SegmentId("enc-1@example.com"), (result, _) => outcomes.Add(result), cts.Token));
        Assert.That(outcomes, Is.EqualTo(new[] { ArticleBodyResult.NotRetrieved }));
    }

    [Test]
    public async Task YencHeadersAsync_TamperedTag_ThrowsFailover_AndReprobeRefetches()
    {
        // F1: a valid-password but tampered-tag article must not release
        // unauthenticated header geometry through the header probe, and a
        // repeated probe must re-fetch (the header cache above stays empty —
        // pinned at the backend layer by
        // HeaderCache_FailedAuthentication_CachesNothing; here the server
        // command count proves nothing was memoised in UsenetSharp either).
        var articles = new Dictionary<string, byte[]> { ["enc-1@example.com"] = Load("tamper-tag.bin") };
        await using var server = await StartServerAsync(articles);
        var context = new YencEncryptionContext(Password);
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () => context,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        await Assert.ThrowsAsync<YencEncryptionFailoverException>(async () =>
            await client.YencHeadersAsync(new SegmentId("enc-1@example.com"), CancellationToken.None));
        await using (var fresh = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () => context,
        }))
        {
            await fresh.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);
            await Assert.ThrowsAsync<YencEncryptionFailoverException>(async () =>
                await fresh.YencHeadersAsync(new SegmentId("enc-1@example.com"), CancellationToken.None));
        }

        Assert.That(server.Commands.Count(c => c.StartsWith("BODY", StringComparison.Ordinal)),
            Is.EqualTo(2));
    }

    [Test]
    public async Task YencHeadersAsync_ProviderEvaluatedExactlyOncePerProbe()
    {
        // F4: UsenetClientOptions documents the provider as evaluated once at
        // each entry point; the encrypted header probe must reuse the
        // caller's snapshot instead of invoking it a second time.
        var articles = new Dictionary<string, byte[]> { ["enc-1@example.com"] = Load("article-single.bin") };
        await using var server = await StartServerAsync(articles);
        var context = new YencEncryptionContext(Password);
        var providerCalls = 0;
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
            YencEncryptionProvider = () =>
            {
                Interlocked.Increment(ref providerCalls);
                return context;
            },
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        var response = await client.YencHeadersAsync(
            new SegmentId("enc-1@example.com"), CancellationToken.None);
        Assert.That(response.YencHeader, Is.Not.Null);
        Assert.That(response.YencHeader!.PartSize, Is.EqualTo(328));
        Assert.That(Volatile.Read(ref providerCalls), Is.EqualTo(1));
    }

    [Test]
    public async Task NoProvider_OrdinaryLoopback_BehaviourUnchanged()
    {
        var plain = Enumerable.Range(0, 512).Select(i => (byte)i).ToArray();
        var body = YencWireBodies.SinglePart(plain, "plain.bin");
        var articles = new Dictionary<string, byte[]> { ["plain@example.com"] = body.Wire[..^3] };
        await using var server = await StartServerAsync(articles);
        await using var client = new UsenetClient(new UsenetClientOptions
        {
            CrcValidation = YencCrcValidationMode.Require,
        });
        await client.ConnectAsync("127.0.0.1", server.Port, false, CancellationToken.None);

        var response = await client.DecodedBodyAsync(
            new SegmentId("plain@example.com"), CancellationToken.None);
        await using var stream = response.Stream!;
        using var output = new MemoryStream();
        await stream.CopyToAsync(output);
        Assert.That(output.ToArray(), Is.EqualTo(plain));
    }
}
