using NzbWebDAV.Database;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Queue.FileProcessors;
using NzbWebDAV.Utils;

namespace NzbWebDAV.Queue.FileAggregators;

public class SevenZipAggregator(
    DavDatabaseClient dbClient,
    DavItem mountDirectory,
    bool checkedFullHealth
) : BaseAggregator
{
    protected override DavDatabaseClient DBClient => dbClient;
    protected override DavItem MountDirectory => mountDirectory;

    public override void UpdateDatabase(List<BaseProcessor.Result> processorResults)
    {
        var sevenZipFiles = processorResults
            .OfType<SevenZipProcessor.Result>()
            .SelectMany(x => x.SevenZipFiles)
            .ToList();

        foreach (var archiveSet in sevenZipFiles.GroupBy(x => x.ArchiveSetId, StringComparer.Ordinal))
            ProcessSevenZipFile(archiveSet.ToList());
    }

    private void ProcessSevenZipFile(List<SevenZipProcessor.SevenZipFile> sevenZipFiles)
    {
        foreach (var sevenZipFile in sevenZipFiles)
        {
            var pathWithinArchive = sevenZipFile.PathWithinArchive;
            var davMultipartFileMeta = sevenZipFile.DavMultipartFileMeta;
            // The processor built this meta before the import context existed;
            // stamp the mounted file's transport-encryption context here (INF-11).
            davMultipartFileMeta.YencEncrypted = Encryption.Encrypted ? true : null;
            davMultipartFileMeta.YencTransportPassword = Encryption.Encrypted ? Encryption.TransportPassword : null;
            var parentDirectory = EnsureParentDirectory(pathWithinArchive);
            var name = ImportableVideoNamer.Normalize(
                SanitizeDavName(Path.GetFileName(pathWithinArchive)),
                sevenZipFile.SniffedVideoExtension,
                mountDirectory.Name,
                allowBaseRename: sevenZipFiles.Count == 1);

            var davMultipartFile = new DavMultipartFile()
            {
                Id = Guid.NewGuid(),
                Metadata = davMultipartFileMeta
            };

            var davItem = DavItem.New(
                id: Guid.NewGuid(),
                parent: parentDirectory,
                name: name,
                fileSize: davMultipartFileMeta.AesParams?.DecodedSize
                    ?? davMultipartFileMeta.FileParts.Sum(x => x.FilePartByteRange.Count),
                type: DavItem.ItemType.UsenetFile,
                subType: DavItem.ItemSubType.MultipartFile,
                releaseDate: sevenZipFile.ReleaseDate,
                lastHealthCheck: checkedFullHealth ? DateTimeOffset.UtcNow : null,
                historyItemId: MountDirectory.HistoryItemId,
                fileBlobId: davMultipartFile.Id,
                nzbBlobId: MountDirectory.HistoryItemId,
                arrDownloadId: MountDirectory.ArrDownloadId
            );

            dbClient.Ctx.Items.Add(davItem);
            dbClient.Ctx.AddBlob(davMultipartFile);
        }
    }
}
