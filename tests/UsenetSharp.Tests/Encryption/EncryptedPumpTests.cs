using System.IO.Pipelines;
using UsenetSharp.Clients;
using UsenetSharp.Encryption;
using UsenetSharp.Models;
using UsenetSharp.Streams;
using UsenetSharpTest.Support;

namespace UsenetSharpTest.Encryption;

/// <summary>
/// INF-14/15/16/18/20 at the decode-pump seam: vendored combined-mode wire
/// articles flow through the production <see cref="NntpYencBodyDecoder"/>
/// (restore → ciphertext CRC → one-segment AEAD) and, in parallel, through
/// the buffer-based encrypted <see cref="YencStream"/>. Fixtures were
/// generated once with the standards reference; tests never encrypt with
/// production code.
/// </summary>
[TestFixture]
public class EncryptedPumpTests
{
    private const string Password = "public-conformance-vector-key-2026";

    // Vendored inside this test project (see TestFixtures/EncryptedArticles/README.md).
    private static string FixtureDir => Path.Join(
        AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles");

    private static byte[] Load(string name) => File.ReadAllBytes(Path.Join(FixtureDir, name));

    private static async Task<(byte[] Bytes, UsenetYencHeader? Headers, Exception? Error, long ObserverBalance)>
        DecodeViaPumpAsync(byte[] article, YencEncryptionContext? context)
    {
        // The decoder expects a wire body ending at the NNTP "." terminator.
        var wire = new byte[article.Length + 3];
        article.CopyTo(wire, 0);
        ".\r\n"u8.CopyTo(wire.AsSpan(article.Length));
        var source = new FragmentedReadStream(wire, [int.MaxValue]);
        using var reader = new NntpLineReader(source);
        var pipe = new Pipe();
        var balance = 0L;
        await using var decodedStream = new DecodedBodyReadStream(
            pipe.Reader.AsStream(), delta => Interlocked.Add(ref balance, delta));
        var headers = new TaskCompletionSource<UsenetYencHeader?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new UsenetClientOptions { CrcValidation = YencCrcValidationMode.Require };
        var decoder = new NntpYencBodyDecoder(
            reader, pipe.Writer, headers, decodedStream, options, 64 * 1024, context);
        using var cts = new CancellationTokenSource();
        using var timeout = new CoalescedReadTimeout(
            TimeSpan.FromSeconds(30), TimeProvider.System, cts.Token);

        Exception? producerError = null;
        var producer = Task.Run(async () =>
        {
            try
            {
                await decoder.ReadAsync(timeout, cts.Token);
                await pipe.Writer.CompleteAsync();
            }
            catch (Exception ex)
            {
                producerError = ex;
                await pipe.Writer.CompleteAsync(ex);
            }
        });

        using var output = new MemoryStream();
        Exception? consumerError = null;
        try
        {
            await decodedStream.CopyToAsync(output);
        }
        catch (Exception ex)
        {
            consumerError = ex;
        }

        await producer;
        UsenetYencHeader? parsed = null;
        if (headers.Task.IsCompletedSuccessfully)
            parsed = await headers.Task;
        return (output.ToArray(), parsed, producerError ?? consumerError, Volatile.Read(ref balance));
    }

    private static async Task<(byte[] Bytes, Exception? Error)> ReadYencStreamAsync(
        byte[] article, YencEncryptionContext context)
    {
        using var stream = new YencStream(new MemoryStream(article, writable: false), context);
        using var output = new MemoryStream();
        try
        {
            await stream.CopyToAsync(output);
            return (output.ToArray(), null);
        }
        catch (Exception ex)
        {
            return (output.ToArray(), ex);
        }
    }

    [Test]
    public async Task SinglePart_CorrectPassword_YieldsExactPlaintext()
    {
        var context = new YencEncryptionContext(Password);
        var (bytes, headers, error, balance) = await DecodeViaPumpAsync(Load("article-single.bin"), context);
        Assert.That(error, Is.Null, error?.ToString());
        Assert.That(bytes, Is.EqualTo(Load("expected-single.bin")));
        Assert.That(headers, Is.Not.Null);
        Assert.That(headers!.PartSize, Is.EqualTo(328));
        Assert.That(balance, Is.EqualTo(0));
    }

    [Test]
    public async Task Multipart_CorrectPassword_YieldsExactPlaintext()
    {
        var context = new YencEncryptionContext(Password);
        var expected = Load("expected-multipart.bin");

        var part1 = await DecodeViaPumpAsync(Load("article-part1.bin"), context);
        Assert.That(part1.Error, Is.Null, part1.Error?.ToString());
        Assert.That(part1.Bytes, Is.EqualTo(expected[..256]));
        Assert.That(part1.Headers!.PartOffset, Is.EqualTo(0));

        var part2 = await DecodeViaPumpAsync(Load("article-part2.bin"), context);
        Assert.That(part2.Error, Is.Null, part2.Error?.ToString());
        Assert.That(part2.Bytes, Is.EqualTo(expected[256..]));
        Assert.That(part2.Headers!.PartOffset, Is.EqualTo(256));
    }

    [Test]
    public async Task YencStream_BufferPath_YieldsExactPlaintext()
    {
        var (bytes, error) = await ReadYencStreamAsync(
            Load("article-single.bin"), new YencEncryptionContext(Password));
        Assert.That(error, Is.Null, error?.ToString());
        Assert.That(bytes, Is.EqualTo(Load("expected-single.bin")));
    }

    [Test]
    public async Task OrdinaryArticle_ThroughEncryptedPump_IsByteIdentical()
    {
        var plain = new byte[] { 0, 1, 2, 250, 251, 10, 13, 61, 42 };
        var body = YencWireBodies.SinglePart(plain, "ordinary.bin");

        var noContext = await DecodeViaPumpAsync(body.Wire[..^3], null);
        Assert.That(noContext.Error, Is.Null, noContext.Error?.ToString());
        Assert.That(noContext.Bytes, Is.EqualTo(plain));
    }

    [Test]
    public async Task WrongPassword_ReleasesZeroBytes_WithFailover()
    {
        var (bytes, _, error, balance) = await DecodeViaPumpAsync(
            Load("article-single.bin"), new YencEncryptionContext("wrong-password"));
        Assert.That(bytes, Is.Empty);
        Assert.That(error, Is.InstanceOf<YencEncryptionFailoverException>());
        Assert.That(balance, Is.EqualTo(0));

        var viaStream = await ReadYencStreamAsync(
            Load("article-single.bin"), new YencEncryptionContext("wrong-password"));
        Assert.That(viaStream.Bytes, Is.Empty);
        Assert.That(viaStream.Error, Is.InstanceOf<YencEncryptionFailoverException>());
    }

    [TestCase("tamper-dual-salt.bin")]
    [TestCase("tamper-dual-index.bin")]
    public async Task Line1Disagreement_ReleasesZeroBytes_WithFailover(string fixture)
    {
        var (bytes, _, error, _) = await DecodeViaPumpAsync(
            Load(fixture), new YencEncryptionContext(Password));
        Assert.That(bytes, Is.Empty);
        Assert.That(error, Is.InstanceOf<YencEncryptionFailoverException>());
    }

    [Test]
    public async Task TamperedTag_ReleasesZeroBytes_AndNoHeaders_WithFailover()
    {
        // F1/F3: parsed-field tag tamper (salt/index agree, CRC valid). The
        // restored headers must NOT be published before the AEAD open —
        // headers stays incomplete/faulted rather than completed.
        var (bytes, headers, error, _) = await DecodeViaPumpAsync(
            Load("tamper-tag.bin"), new YencEncryptionContext(Password));
        Assert.That(bytes, Is.Empty);
        Assert.That(headers, Is.Null);
        Assert.That(error, Is.InstanceOf<YencEncryptionFailoverException>());
    }

    [Test]
    public async Task OversizedArticle_ReleasesZeroBytes_WithFailover_NoHang()
    {
        // F5: an "article" far beyond the one-segment accumulation ceiling
        // (default AbandonedBodyDrainLimit = 1 MiB) fails over with zero
        // bytes instead of accumulating without bound.
        var article = Load("article-single.bin");
        var oversized = new byte[2 * 1024 * 1024];
        for (var i = 0; i < oversized.Length; i++)
            oversized[i] = article[i % article.Length];
        var (bytes, _, error, _) = await DecodeViaPumpAsync(
            oversized, new YencEncryptionContext(Password));
        Assert.That(bytes, Is.Empty);
        Assert.That(error, Is.InstanceOf<YencEncryptionFailoverException>());
    }

    [Test]
    public async Task TruncatedArticle_ReleasesZeroBytes_WithFailover()
    {
        var article = Load("article-single.bin");
        var truncated = article[..(article.Length / 2)];
        var (bytes, _, error, _) = await DecodeViaPumpAsync(
            truncated, new YencEncryptionContext(Password));
        Assert.That(bytes, Is.Empty);
        Assert.That(error, Is.Not.Null);
        Assert.That(error, Is.InstanceOf<YencEncryptionFailoverException>()
            .Or.InstanceOf<UsenetSharp.Exceptions.UsenetProtocolException>());
    }
}
