using Microsoft.EntityFrameworkCore;
using NzbWebDAV.Config;
using NzbWebDAV.Database;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Exceptions;
using NzbWebDAV.Services.Repair;
using NzbWebDAV.Tests.Database;

namespace NzbWebDAV.Tests.Services.Repair;

/// <summary>
/// INF-13 wrong-password durability (plan §4.6), written at the level testable
/// NOW: the persistence classification seam. An authentication failure must
/// never write CorruptSegmentIndices/MissingSegmentIndices — the password
/// itself may be wrong, so a corrected password must read the file with no
/// persistent marks. DEPENDENCY: the end-to-end form (wrong-password read via
/// the decrypting decoder, then corrected-password read) needs Phase 3
/// (INF-14/15); Phase 3 wires MultiSegmentStream's auth failures through
/// Par2RepairTriggerSink.ReportAuthenticationFailure into this same seam.
/// </summary>
[Collection(nameof(ConfigPathCollection))]
public sealed class YencAuthFailureDurabilityTests : IAsyncLifetime
{
    private readonly string _configRoot =
        Path.Join(Path.GetTempPath(), $"nzbdav-auth-durability-{Guid.NewGuid():N}");
    private string? _previousConfigPath;
    private ConfigManager _config = null!;

    public Task InitializeAsync()
    {
        _previousConfigPath = Environment.GetEnvironmentVariable("CONFIG_PATH");
        Directory.CreateDirectory(_configRoot);
        Environment.SetEnvironmentVariable("CONFIG_PATH", _configRoot);
        DavDatabaseContext.ResetOptionsForTests();
        _config = new ConfigManager();
        _config.UpdateValues(
        [
            new ConfigItem { ConfigName = ConfigKeys.RepairEnable, ConfigValue = "true" },
        ]);
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        Environment.SetEnvironmentVariable("CONFIG_PATH", _previousConfigPath);
        DavDatabaseContext.ResetOptionsForTests();
        try { Directory.Delete(_configRoot, recursive: true); } catch (IOException) { /* best effort */ }
        return Task.CompletedTask;
    }

    [Fact]
    public void Classifier_AuthenticationFailure_SuppressesAllMarks()
    {
        Assert.False(Par2RepairService.CanPersistDamageMarks(
            isAuthenticationFailure: true, missingCount: 2, corruptCount: 3));
        Assert.False(Par2RepairService.CanPersistDamageMarks(
            isAuthenticationFailure: true, missingCount: 0, corruptCount: 1));
        Assert.True(Par2RepairService.CanPersistDamageMarks(
            isAuthenticationFailure: false, missingCount: 1, corruptCount: 0));
        Assert.True(Par2RepairService.CanPersistDamageMarks(
            isAuthenticationFailure: false, missingCount: 0, corruptCount: 1));
        Assert.False(Par2RepairService.CanPersistDamageMarks(
            isAuthenticationFailure: false, missingCount: 0, corruptCount: 0));
    }

    [Fact]
    public void IsAuthenticationFailure_RecognisesMarkerAndPhase1Failover()
    {
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(
            new YencAuthenticationException("seg@example.test")));
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(
            new UsenetCorruptArticleException("seg@example.test", "provider",
                new UsenetSharp.Encryption.YencEncryptionFailoverException("tag mismatch"))));
        Assert.True(YencAuthenticationException.IsAuthenticationFailure(
            new InvalidOperationException("outer",
                new YencAuthenticationException("seg@example.test"))));
        Assert.False(YencAuthenticationException.IsAuthenticationFailure(
            new UsenetCorruptArticleException("seg@example.test", "provider",
                new InvalidOperationException("crc mismatch"))));
        Assert.False(YencAuthenticationException.IsAuthenticationFailure(null));
        Assert.False(YencAuthenticationException.IsAuthenticationFailure(
            new UsenetSharp.Encryption.YencEncryptionLocalException("no password")));
    }

    [Fact]
    public async Task AuthFailureReport_PersistsNoMarks_ThenCorruptionStillRecords()
    {
        var segments = NewSegmentIds(3);
        var (item, _) = await AddEncryptedFileAsync(segments);
        var service = NewService();

        // Wrong-password style failure: classified as authentication, drained
        // through the production persistence path — no marks may persist.
        await service.ProcessAuthenticationFailureForTestsAsync(
            item.Path, segments[1], CancellationToken.None);

        var afterAuth = await ReadCurrentBlobAsync(item.Id);
        Assert.Null(afterAuth.CorruptSegmentIndices);
        Assert.Null(afterAuth.MissingSegmentIndices);
        Assert.Equal(true, afterAuth.YencEncrypted);

        // The same file is not poisoned: a genuine provider-corruption report
        // afterwards still records (and a corrected password could clear it).
        await service.ProcessCorruptionEventForTestsAsync(item.Path, segments[1], CancellationToken.None);

        var afterCorrupt = await ReadCurrentBlobAsync(item.Id);
        Assert.Equal([1], afterCorrupt.CorruptSegmentIndices!);
    }

    [Fact]
    public async Task AuthFailureReport_OnOrdinaryFile_AlsoPersistsNoMarks()
    {
        var segments = NewSegmentIds(3);
        var (item, _) = await AddEncryptedFileAsync(segments, encrypted: false);
        var service = NewService();

        await service.ProcessAuthenticationFailureForTestsAsync(
            item.Path, segments[0], CancellationToken.None);

        var blob = await ReadCurrentBlobAsync(item.Id);
        Assert.Null(blob.CorruptSegmentIndices);
        Assert.Null(blob.MissingSegmentIndices);
    }

    [Fact]
    public async Task DiscoveredDamage_OnEncryptedFile_GenuineDamageStillRecords()
    {
        var segments = NewSegmentIds(3);
        var (item, _) = await AddEncryptedFileAsync(segments);
        var service = NewService();

        // PAR2-discovered damage with no authentication classification (e.g. a
        // confirmed provider miss) is genuine evidence even on an encrypted
        // file — the F2 narrowing must keep recording it.
        await service.PersistDiscoveredDamageForTestsAsync(
            item,
            await ReadCurrentBlobAsync(item.Id),
            missingIndices: [1],
            corruptIndices: [2],
            isAuthenticationFailure: false,
            CancellationToken.None);

        var blob = await ReadCurrentBlobAsync(item.Id);
        Assert.Equal([1], blob.MissingSegmentIndices!);
        Assert.Equal([2], blob.CorruptSegmentIndices!);
        Assert.Equal(true, blob.YencEncrypted);
    }

    [Fact]
    public async Task DiscoveredDamage_OnEncryptedFile_AuthFailurePersistsNoMarks()
    {
        var segments = NewSegmentIds(3);
        var (item, _) = await AddEncryptedFileAsync(segments);
        var service = NewService();

        await service.PersistDiscoveredDamageForTestsAsync(
            item,
            await ReadCurrentBlobAsync(item.Id),
            missingIndices: [1],
            corruptIndices: [2],
            isAuthenticationFailure: true,
            CancellationToken.None);

        var blob = await ReadCurrentBlobAsync(item.Id);
        Assert.Null(blob.MissingSegmentIndices);
        Assert.Null(blob.CorruptSegmentIndices);
        Assert.Equal(true, blob.YencEncrypted);
    }

    private Par2RepairService NewService() =>
        new(_config, null!, new RepairPatchStore(Path.Join(_configRoot, "patches"), 1024 * 1024));

    private async Task<(DavItem Item, Guid BlobId)> AddEncryptedFileAsync(
        string[] segmentIds, bool encrypted = true)
    {
        await using var context = new DavDatabaseContext();
        await context.Database.MigrateAsync();

        var itemId = Guid.NewGuid();
        var blobId = Guid.NewGuid();
        await BlobStore.WriteBlob(blobId, new DavNzbFile
        {
            Id = itemId,
            SegmentIds = segmentIds,
            YencEncrypted = encrypted ? true : null,
            YencTransportPassword = encrypted ? "wrong-password-probe" : null,
        });

        var item = DavItem.New(
            itemId,
            DavItem.ContentFolder,
            $"file-{itemId:N}.bin",
            fileSize: 300,
            DavItem.ItemType.UsenetFile,
            DavItem.ItemSubType.NzbFile,
            releaseDate: DateTimeOffset.UtcNow.AddDays(-1),
            lastHealthCheck: null,
            historyItemId: null,
            fileBlobId: blobId);
        context.Items.Add(item);
        await context.SaveChangesAsync();
        return (item, blobId);
    }

    private static async Task<DavNzbFile> ReadCurrentBlobAsync(Guid itemId)
    {
        await using var context = new DavDatabaseContext();
        var item = await context.Items.AsNoTracking().SingleAsync(x => x.Id == itemId);
        var blob = await BlobStore.ReadBlob<DavNzbFile>(item.FileBlobId!.Value);
        return blob!;
    }

    private static string[] NewSegmentIds(int count) =>
        Enumerable.Range(0, count).Select(i => $"seg{i}-{Guid.NewGuid():N}@test").ToArray();
}
