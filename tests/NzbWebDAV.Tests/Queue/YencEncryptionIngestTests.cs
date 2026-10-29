using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using NzbWebDAV.Clients.Usenet;
using NzbWebDAV.Config;
using NzbWebDAV.Database;
using NzbWebDAV.Database.Interceptors;
using NzbWebDAV.Database.MigrationHelpers;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Clients.Usenet.Models;
using NzbWebDAV.Exceptions;
using NzbWebDAV.Models;
using NzbWebDAV.Models.Nzb;
using NzbWebDAV.Queue;
using NzbWebDAV.Services;
using NzbWebDAV.Tests.Database;
using NzbWebDAV.Utils;
using NzbWebDAV.Tests.Fakes;
using NzbWebDAV.Websocket;
using UsenetSharp.Models;

namespace NzbWebDAV.Tests.Queue;

/// <summary>
/// INF-10/11: ingest gate (plan §4.1) and context reaching the aggregators (§4.2).
/// Gate cases run through the real QueueItemProcessor against FakeNntpClient
/// counters; persistence cases assert the mounted DavNzbFile blob fields.
/// </summary>
[Collection(nameof(ConfigPathCollection))]
public sealed class YencEncryptionIngestTests : IAsyncLifetime
{
    private const string MetaPassword = "transport-marker-pw";
    private const string FilenamePassword = "filename-override-pw";
    private const string SegmentId = "enc-seg1@example.test";

    private readonly string _root = Path.Join(Path.GetTempPath(), "yenc-ingest-" + Guid.NewGuid().ToString("N"));
    private string? _previous;

    public async Task InitializeAsync()
    {
        _previous = Environment.GetEnvironmentVariable("CONFIG_PATH");
        Directory.CreateDirectory(_root);
        Environment.SetEnvironmentVariable("CONFIG_PATH", _root);
        DavDatabaseContext.ResetOptionsForTests();
        await using var context = new DavDatabaseContext();
        await context.Database.MigrateAsync();
    }

    public Task DisposeAsync()
    {
        Environment.SetEnvironmentVariable("CONFIG_PATH", _previous);
        DavDatabaseContext.ResetOptionsForTests();
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { /* best effort */ }
        return Task.CompletedTask;
    }

    // ---- INF-10: decision function (fail closed, Body §8) ----

    [Fact]
    public void FromMetadata_MarkerAbsent_MetaPasswordIsOrdinary()
    {
        var context = YencEncryptionContext.FromMetadata(
            new Dictionary<string, string> { ["password"] = MetaPassword }, filenamePassword: null);
        Assert.False(context.Encrypted);
        Assert.Null(context.TransportPassword);
    }

    [Theory]
    [InlineData("false")]
    [InlineData("yes")]
    [InlineData("")]
    public void FromMetadata_MarkerNotTrue_IsOrdinary(string marker)
    {
        var context = YencEncryptionContext.FromMetadata(
            new Dictionary<string, string>
            {
                ["yenc_encrypted"] = marker,
                ["password"] = MetaPassword,
            },
            filenamePassword: null);
        Assert.False(context.Encrypted);
    }

    [Theory]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData(" true ")]
    [InlineData(" True ")]
    public void FromMetadata_MarkerTrue_UsesMetaPassword(string marker)
    {
        var context = YencEncryptionContext.FromMetadata(
            new Dictionary<string, string>
            {
                ["yenc_encrypted"] = marker,
                ["password"] = MetaPassword,
            },
            filenamePassword: null);
        Assert.True(context.Encrypted);
        Assert.Equal(MetaPassword, context.TransportPassword);
    }

    [Fact]
    public void FromMetadata_FilenamePasswordWinsOverMeta()
    {
        var context = YencEncryptionContext.FromMetadata(
            new Dictionary<string, string>
            {
                ["yenc_encrypted"] = "true",
                ["password"] = MetaPassword,
            },
            filenamePassword: FilenamePassword);
        Assert.True(context.Encrypted);
        Assert.Equal(FilenamePassword, context.TransportPassword);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FromMetadata_EncryptedWithoutPassword_FailsClosed(string? metaPassword)
    {
        var metadata = new Dictionary<string, string> { ["yenc_encrypted"] = "true" };
        if (metaPassword is not null)
            metadata["password"] = metaPassword;

        var ex = Assert.Throws<NonRetryableDownloadException>(
            () => YencEncryptionContext.FromMetadata(metadata, filenamePassword: null));
        Assert.Contains("Encrypted NZB", ex.Message);
        Assert.DoesNotContain(MetaPassword, ex.Message);
    }

    [Theory]
    [InlineData("1.2", "XChaCha20-Poly1305")]
    [InlineData(" 1.2 ", "xchacha20-poly1305")]
    [InlineData("1.2", "XCHACha20-POLY1305")]
    public void FromMetadata_ValidVersionAndCipher_Passes(string version, string cipher)
    {
        var context = YencEncryptionContext.FromMetadata(
            new Dictionary<string, string>
            {
                ["yenc_encrypted"] = "true",
                ["yenc_version"] = version,
                ["yenc_cipher"] = cipher,
                ["password"] = MetaPassword,
            },
            filenamePassword: null);
        Assert.True(context.Encrypted);
        Assert.Equal(MetaPassword, context.TransportPassword);
    }

    [Theory]
    [InlineData("1.3", "XChaCha20-Poly1305")]
    [InlineData(" 1.3 ", "XChaCha20-Poly1305")]
    [InlineData("", "XChaCha20-Poly1305")]
    [InlineData("1.2", "AES-GCM")]
    [InlineData("1.2", "")]
    [InlineData("2.0", "AES")]
    public void FromMetadata_InvalidVersionOrCipher_FailsClosed(string version, string cipher)
    {
        Assert.Throws<NonRetryableDownloadException>(() => YencEncryptionContext.FromMetadata(
            new Dictionary<string, string>
            {
                ["yenc_encrypted"] = "true",
                ["yenc_version"] = version,
                ["yenc_cipher"] = cipher,
                ["password"] = MetaPassword,
            },
            filenamePassword: null));
    }

    [Fact]
    public void FromMetadata_InvalidMarkerMetadataIgnoredWhenOrdinary()
    {
        // Without the marker, version/cipher metas are not consumed (Body §8).
        var context = YencEncryptionContext.FromMetadata(
            new Dictionary<string, string>
            {
                ["yenc_version"] = "9.9",
                ["yenc_cipher"] = "AES",
                ["password"] = MetaPassword,
            },
            filenamePassword: null);
        Assert.False(context.Encrypted);
    }

    // ---- INF-10: full processor gate (zero fetches, failed history) ----

    [Fact]
    public async Task EncryptedWithoutPassword_FailsClosedWithZeroFetches()
    {
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        var outcome = await RunProcessorAsync(
            EncryptedNzb(password: null), "release.nzb", fake);

        Assert.Equal(HistoryItem.DownloadStatusOption.Failed, outcome.Status);
        Assert.Contains("Encrypted NZB", outcome.FailMessage);
        Assert.Equal(0, fake.BodyRequestCount);
        Assert.Equal(0, fake.HeaderProbeCount);
        Assert.Empty(fake.StatRequestCounts);
        Assert.Empty(outcome.Items);
    }

    [Fact]
    public async Task EncryptedWithInvalidVersion_FailsClosedWithZeroFetches()
    {
        var fake = new FakeNntpClient(new Dictionary<string, byte[]>());
        var outcome = await RunProcessorAsync(
            EncryptedNzb(password: MetaPassword, version: "1.3"), "release.nzb", fake);

        Assert.Equal(HistoryItem.DownloadStatusOption.Failed, outcome.Status);
        Assert.Equal(0, fake.BodyRequestCount);
        Assert.Equal(0, fake.HeaderProbeCount);
        Assert.Empty(outcome.Items);
    }

    // ---- INF-11: context reaches the aggregators (direct file mount) ----
    // NOTE: these mount cases use FakeNntpClient's ordinary yEnc articles to
    // pin gate + persistence. Encrypted wire-article probing itself is pinned
    // separately by FetchFirstSegmentsEncryptedProbeTests (INF-22/B2), which
    // drives FetchFirstSegmentsStep over the INF-05 encrypted fake under
    // YencEncryptionRuntimeContext.Begin.

    [Fact]
    public async Task EncryptedWithMetaPassword_MountsWithTransportContext()
    {
        var payload = new byte[4096];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }.CopyTo(payload, 0);
        var fake = SingleSegmentClient(payload);
        var outcome = await RunProcessorAsync(
            EncryptedNzb(password: MetaPassword), "release.nzb", fake);

        Assert.True(outcome.Status == HistoryItem.DownloadStatusOption.Completed,
            $"expected Completed, got {outcome.Status}: {outcome.FailMessage}");
        var blob = await ReadMountedNzbFileAsync();
        Assert.Equal(true, blob.YencEncrypted);
        Assert.Equal(MetaPassword, blob.YencTransportPassword);
    }

    [Fact]
    public async Task EncryptedWithFilenamePassword_FilenameWinsAtMount()
    {
        var payload = new byte[4096];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }.CopyTo(payload, 0);
        var fake = SingleSegmentClient(payload);
        var outcome = await RunProcessorAsync(
            EncryptedNzb(password: MetaPassword),
            $"release {{{{{FilenamePassword}}}}}.nzb",
            fake);

        Assert.Equal(HistoryItem.DownloadStatusOption.Completed, outcome.Status);
        var blob = await ReadMountedNzbFileAsync();
        Assert.Equal(true, blob.YencEncrypted);
        Assert.Equal(FilenamePassword, blob.YencTransportPassword);
    }

    [Fact]
    public async Task OrdinaryWithMetaPassword_MountsUnencrypted()
    {
        var payload = new byte[4096];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }.CopyTo(payload, 0);
        var fake = SingleSegmentClient(payload);
        var outcome = await RunProcessorAsync(
            EncryptedNzb(password: MetaPassword, encrypted: false), "release.nzb", fake);

        Assert.Equal(HistoryItem.DownloadStatusOption.Completed, outcome.Status);
        var blob = await ReadMountedNzbFileAsync();
        Assert.Null(blob.YencEncrypted);
        Assert.Null(blob.YencTransportPassword);
    }

    [Fact]
    public async Task EncryptedSecondNamespace_MountsWithTransportContext()
    {
        // Body §8 consumer req 3: the second canonical NZB namespace parses.
        var payload = new byte[4096];
        new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }.CopyTo(payload, 0);
        var fake = SingleSegmentClient(payload);
        var nzb = Encoding.UTF8.GetBytes($"""
            <?xml version="1.0" encoding="utf-8"?>
            <nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
              <head>
                <meta type="yenc_encrypted">true</meta>
                <meta type="password">{MetaPassword}</meta>
              </head>
              <file poster="poster@example.test" date="1" subject="&quot;data.mkv&quot; yEnc (1/1)">
                <groups><group>alt.binaries.test</group></groups>
                <segments>
                  <segment bytes="{payload.Length}" number="1">{SegmentId}</segment>
                </segments>
              </file>
            </nzb>
            """);
        var outcome = await RunProcessorAsync(nzb, "release.nzb", fake);

        Assert.Equal(HistoryItem.DownloadStatusOption.Completed, outcome.Status);
        var blob = await ReadMountedNzbFileAsync();
        Assert.Equal(true, blob.YencEncrypted);
        Assert.Equal(MetaPassword, blob.YencTransportPassword);
    }

    private static FakeNntpClient SingleSegmentClient(byte[] payload) =>
        new(
            new Dictionary<string, byte[]> { [SegmentId] = payload },
            useCachedYencStreams: true,
            segmentRanges: new Dictionary<string, LongRange>
            {
                [SegmentId] = new(0, payload.Length),
            },
            yencHeaders: new Dictionary<string, UsenetYencHeader>
            {
                [SegmentId] = new()
                {
                    FileName = "data.mkv",
                    FileSize = payload.Length,
                    LineLength = 128,
                    PartNumber = 1,
                    TotalParts = 1,
                    HasTotalParts = true,
                    PartOffset = 0,
                    PartSize = payload.Length,
                },
            });

    /// <summary>
    /// FakeNntpClient cannot serve ARTICLE responses (its DecodedArticleAsync
    /// throws); FetchFirstSegmentsStep needs one. Mirror OmittedSegmentImportTests.
    /// </summary>
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

    private static byte[] EncryptedNzb(string? password, string? version = null, bool encrypted = true)
    {
        var head = new StringBuilder();
        if (encrypted)
            head.Append("<meta type=\"yenc_encrypted\">true</meta>");
        if (password is not null)
            head.Append($"<meta type=\"password\">{password}</meta>");
        if (version is not null)
            head.Append($"<meta type=\"yenc_version\">{version}</meta>");
        return Encoding.UTF8.GetBytes($"""
            <?xml version="1.0" encoding="utf-8"?>
            <nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
              <head>{head}</head>
              <file poster="poster@example.test" date="1" subject="&quot;data.mkv&quot; yEnc (1/1)">
                <groups><group>alt.binaries.test</group></groups>
                <segments>
                  <segment bytes="4096" number="1">{SegmentId}</segment>
                </segments>
              </file>
            </nzb>
            """);
    }

    private sealed record Outcome(
        HistoryItem.DownloadStatusOption Status, string? FailMessage, List<DavItem> Items);

    private async Task<Outcome> RunProcessorAsync(byte[] nzb, string fileName, INntpClient client)
    {
        await using var context = NewContext();
        await context.Database.MigrateAsync();
        var queueItem = new QueueItem
        {
            Id = Guid.NewGuid(),
            CreatedAt = DateTime.UtcNow,
            FileName = fileName,
            JobName = FilenameUtil.GetJobName(fileName),
            NzbFileSize = nzb.Length,
            TotalSegmentBytes = 4096,
            Category = "other",
            Priority = QueueItem.PriorityOption.Normal,
            PostProcessing = QueueItem.PostProcessingOption.None,
        };
        context.QueueItems.Add(queueItem);
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();
        queueItem = await context.QueueItems.SingleAsync(q => q.Id == queueItem.Id);

        var config = new ConfigManager();
        using var gate = new HealthCheckConnectionGate(config);
        await using var nzbStream = new MemoryStream(nzb);
        var processor = new QueueItemProcessor(
            queueItem, nzbStream, new DavDatabaseClient(context),
            client is FakeNntpClient fake ? new ArticleServingClient(fake) : client, config,
            new WebsocketManager(), new Progress<int>(), gate, CancellationToken.None);
        await processor.ProcessAsync();

        context.ChangeTracker.Clear();
        Assert.Empty(await context.QueueItems.AsNoTracking().ToListAsync());
        var history = Assert.Single(await context.HistoryItems.AsNoTracking().ToListAsync());
        var items = await context.Items.AsNoTracking()
            .Where(item => item.SubType == DavItem.ItemSubType.NzbFile)
            .ToListAsync();
        return new Outcome(history.DownloadStatus, history.FailMessage, items);
    }

    private async Task<DavNzbFile> ReadMountedNzbFileAsync()
    {
        await using var context = NewContext();
        var item = Assert.Single(await context.Items.AsNoTracking()
            .Where(i => i.SubType == DavItem.ItemSubType.NzbFile).ToListAsync());
        var client = new DavDatabaseClient(context);
        var blob = await client.GetDavNzbFileAsync(item);
        Assert.NotNull(blob);
        return blob;
    }

    private static DavDatabaseContext NewContext()
    {
        var options = new DbContextOptionsBuilder<DavDatabaseContext>()
            .UseSqlite($"Data Source={DavDatabaseContext.DatabaseFilePath}")
            .AddInterceptors(new SqliteForeignKeyEnabler())
            .ReplaceService<IMigrationsSqlGenerator, SqliteMigrationsSqlGenerator<SqliteMigrationsSqlGenerator>>()
            .Options;
        return new DavDatabaseContext(options);
    }
}
