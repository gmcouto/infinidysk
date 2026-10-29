using NzbWebDAV.Clients.Usenet;
using NzbWebDAV.Clients.Usenet.Contexts;
using NzbWebDAV.Config;
using NzbWebDAV.Clients.Usenet.Models;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Models.Nzb;
using NzbWebDAV.Queue.DeobfuscationSteps._1.FetchFirstSegment;
using NzbWebDAV.Tests.Fakes;
using UsenetSharp.Models;

namespace NzbWebDAV.Tests.Queue;

/// <summary>
/// B2/INF-22: queue first-segment probes over encrypted wire articles.
/// FetchFirstSegmentsStep runs under YencEncryptionRuntimeContext.Begin
/// (the QueueItemProcessor scope shape); the INF-05 fake serves the vendored
/// encrypted articles through the production restore+AEAD path, so the probe
/// must see plaintext-world headers and must NOT mark the file
/// missing-first-segment. NOTE: GetPar2FileDescriptorsStep remains
/// construction-proven only — no encrypted-PAR2 fixture exists in the
/// vendored set, so there is no descriptor-level encrypted probe test.
/// </summary>
public sealed class FetchFirstSegmentsEncryptedProbeTests
{
    private const string Password = "public-conformance-vector-key-2026";
    private const string SingleId = "enc-single@example.com";
    private const string Part1Id = "enc-p1@example.com";

    private static string FixtureDir => Path.Join(
        AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles");

    private static byte[] Load(string name) => File.ReadAllBytes(Path.Join(FixtureDir, name));

    private static FakeNntpClient EncryptedFake()
    {
        // Ambient mode with no fake-owned context: decryption can only come
        // from the YencEncryptionRuntimeContext.Begin(Password) scope the
        // test installs around FetchFirstSegments — mirroring production
        // BaseNntpClient. If the probe ran outside that scope it would fail
        // closed instead of silently decrypting with a stashed context.
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        fake.UseAmbientEncryptionContext = true;
        fake.ServeEncrypted(SingleId, Load("article-single.bin"));
        fake.ServeEncrypted(Part1Id, Load("article-part1.bin"));
        return fake;
    }

    private static ConfigManager NonPipelinedConfig()
    {
        var config = new ConfigManager();
        config.UpdateValues(
        [
            new ConfigItem
            {
                ConfigName = ConfigKeys.UsenetPipeliningEnabled,
                ConfigValue = "false",
            },
            new ConfigItem
            {
                ConfigName = ConfigKeys.UsenetMaxQueueConnections,
                ConfigValue = "1",
            },
        ]);
        return config;
    }

    private static NzbFile FileFor(string segmentId, string subject, long bytes) => new()
    {
        Subject = subject,
        Segments =
        {
            new NzbSegment { MessageId = segmentId, Bytes = bytes },
        },
    };

    // FetchFirstSegment needs DecodedArticleAsync; FakeNntpClient does not
    // implement ARTICLE, so mirror YencEncryptionIngestTests.ArticleServingClient.
    private sealed class ArticleServingClient(INntpClient inner) : WrappingNntpClient(inner)
    {
        public override Task<UsenetDecodedArticleResponse> DecodedArticleAsync(
            SegmentId segmentId, CancellationToken cancellationToken) =>
            DecodedArticleAsync(segmentId, null, cancellationToken);

        public override async Task<UsenetDecodedArticleResponse> DecodedArticleAsync(
            SegmentId segmentId, ArticleBodyCompletionHandler? onConnectionReadyAgain,
            CancellationToken cancellationToken)
        {
            var body = await InnerClient.DecodedBodyAsync(segmentId, onConnectionReadyAgain, cancellationToken);
            return new UsenetDecodedArticleResponse
            {
                SegmentId = body.SegmentId,
                ResponseCode = 220,
                ResponseMessage = "220 test article",
                Stream = body.Stream!,
                ArticleHeaders = new UsenetArticleHeader
                {
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Date"] = DateTimeOffset.UtcNow.ToString("R"),
                    },
                },
            };
        }
    }

    [Fact]
    public async Task FetchFirstSegments_EncryptedSinglePart_PlaintextWorldHeader_NotMissing()
    {
        var fake = EncryptedFake();
        using var client = new ArticleServingClient(fake);
        var file = FileFor(SingleId, "\"file-a.bin\" yEnc", 328);

        using (YencEncryptionRuntimeContext.Begin(Password))
        {
            var result = Assert.Single(await FetchFirstSegmentsStep.FetchFirstSegments(
                [file], client, NonPipelinedConfig(), CancellationToken.None));

            Assert.False(result.MissingFirstSegment);
            Assert.NotNull(result.Header);
            // Plaintext-world geometry: single-part article is 328 bytes.
            Assert.Equal(328, result.Header!.PartSize);
            Assert.Equal(0, result.Header.PartOffset);
            Assert.Equal(Load("expected-single.bin"), result.First16KB);
        }
    }

    [Fact]
    public async Task FetchFirstSegments_EncryptedMultipartPart_PlaintextWorldHeader_NotMissing()
    {
        var fake = EncryptedFake();
        using var client = new ArticleServingClient(fake);
        var file = FileFor(Part1Id, "\"file-b.bin\" yEnc", 256);

        using (YencEncryptionRuntimeContext.Begin(Password))
        {
            var result = Assert.Single(await FetchFirstSegmentsStep.FetchFirstSegments(
                [file], client, NonPipelinedConfig(), CancellationToken.None));

            Assert.False(result.MissingFirstSegment);
            Assert.NotNull(result.Header);
            // Multipart part 1 of file-b.bin: 256 authenticated plaintext bytes.
            Assert.Equal(256, result.Header!.PartSize);
            Assert.Equal(0, result.Header.PartOffset);
            Assert.Equal(Load("expected-multipart.bin")[..256], result.First16KB);
        }
    }
}
