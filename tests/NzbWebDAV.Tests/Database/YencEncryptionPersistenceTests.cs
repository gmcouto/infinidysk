using MemoryPack;
using NzbWebDAV.Database.Models;
using NzbWebDAV.Models;
using NzbWebDAV.Services.Repair;

namespace NzbWebDAV.Tests.Database;

/// <summary>
/// INF-11/12: MemoryPack persistence of the yEnc transport-encryption context.
/// DavNzbFile orders 10/11; DavMultipartFile.Meta orders 7/8 (meta-level only —
/// LazyRarResolver rebuilds parts under the same Meta, so FilePart/PendingPart/
/// RarPart need no fields; DavRarFile's Orders 2/3 context fields were
/// dropped in Phase 4 (INF-21/Finding-4): no writer exists — every current
/// import mounts RAR as DavMultipartFile. Legacy blobs (fields absent) read as
/// ordinary. DavNzbFileBlobUpdater.Clone carries the fields (Meta clones in
/// LazyRarResolver copy them explicitly).
/// </summary>
public partial class YencEncryptionPersistenceTests
{
    private const string TransportPassword = "transport-marker-pw";

    /// <summary>Pre-change DavNzbFile shape (orders 0–9 only).</summary>
    [MemoryPackable(GenerateType.VersionTolerant)]
    public partial class LegacyDavNzbFile
    {
        [MemoryPackOrder(0)] public Guid Id { get; set; }
        [MemoryPackOrder(1)] public string[] SegmentIds { get; set; } = [];
        [MemoryPackOrder(2)] public LongRange[]? SegmentByteRanges { get; set; }
        [MemoryPackOrder(3)] public string[][]? SegmentFallbackIds { get; set; }
        [MemoryPackOrder(4)] public int[]? MissingSegmentIndices { get; set; }
        [MemoryPackOrder(5)] public byte? ContainerClass { get; set; }
        [MemoryPackOrder(6)] public long? CriticalHeadEndExclusive { get; set; }
        [MemoryPackOrder(7)] public int[]? CorruptSegmentIndices { get; set; }
        [MemoryPackOrder(8)] public bool? SegmentByteRangesTrusted { get; set; }
        [MemoryPackOrder(9)] public Par2FileProof? VerificationProof { get; set; }
    }

    /// <summary>Pre-change DavMultipartFile.Meta shape (orders 0–6 only).</summary>
    [MemoryPackable(GenerateType.VersionTolerant)]
    public partial class LegacyMeta
    {
        [MemoryPackOrder(0)] public AesParams? AesParams { get; set; }
        [MemoryPackOrder(1)] public DavMultipartFile.FilePart[] FileParts { get; set; } = [];
        [MemoryPackOrder(2)] public bool IsLazy { get; set; }
        [MemoryPackOrder(3)] public string? PathInArchive { get; set; }
        [MemoryPackOrder(4)] public string? ArchivePassword { get; set; }
        [MemoryPackOrder(5)] public DavMultipartFile.PendingPart[] PendingParts { get; set; } = [];
        [MemoryPackOrder(6)] public long? ExpectedFileSize { get; set; }
    }

    /// <summary>Pre-change DavRarFile shape (orders 0–1 only).</summary>
    [MemoryPackable(GenerateType.VersionTolerant)]
    public partial class LegacyDavRarFile
    {
        [MemoryPackOrder(0)] public Guid Id { get; set; }
        [MemoryPackOrder(1)] public DavRarFile.RarPart[] RarParts { get; set; } = [];
    }

    /// <summary>
    /// F5: legacy shape that DID carry the dropped Orders 2/3
    /// (bool?/string?) encryption fields, populated. Deserializing it as the
    /// current DavRarFile (which dropped those orders in Phase 4) must
    /// tolerate/skip them and preserve RarParts — proving dropped-field
    /// tolerance for blobs written while Orders 2/3 existed.
    /// </summary>
    [MemoryPackable(GenerateType.VersionTolerant)]
    public partial class LegacyDavRarFileWithDroppedOrders
    {
        [MemoryPackOrder(0)] public Guid Id { get; set; }
        [MemoryPackOrder(1)] public DavRarFile.RarPart[] RarParts { get; set; } = [];
        [MemoryPackOrder(2)] public bool? YencEncrypted { get; set; }
        [MemoryPackOrder(3)] public string? YencTransportPassword { get; set; }
    }

    [Fact]
    public void DavNzbFile_EncryptionContext_RoundTrips()
    {
        var original = new DavNzbFile
        {
            Id = Guid.NewGuid(),
            SegmentIds = ["seg0"],
            YencEncrypted = true,
            YencTransportPassword = TransportPassword,
        };

        var restored = MemoryPackSerializer.Deserialize<DavNzbFile>(
            MemoryPackSerializer.Serialize(original))!;

        Assert.Equal(true, restored.YencEncrypted);
        Assert.Equal(TransportPassword, restored.YencTransportPassword);
        Assert.Equal(original.SegmentIds, restored.SegmentIds);
    }

    [Fact]
    public void DavNzbFile_LegacyBlob_ReadsAsOrdinary()
    {
        var legacy = new LegacyDavNzbFile
        {
            Id = Guid.NewGuid(),
            SegmentIds = ["seg0"],
        };

        var restored = MemoryPackSerializer.Deserialize<DavNzbFile>(
            MemoryPackSerializer.Serialize(legacy))!;

        Assert.Null(restored.YencEncrypted);
        Assert.Null(restored.YencTransportPassword);
        Assert.Equal(["seg0"], restored.SegmentIds);
    }

    [Fact]
    public void DavMultipartMeta_EncryptionContext_RoundTrips()
    {
        var original = new DavMultipartFile
        {
            Id = Guid.NewGuid(),
            Metadata = new DavMultipartFile.Meta
            {
                FileParts = [],
                YencEncrypted = true,
                YencTransportPassword = TransportPassword,
            },
        };

        var restored = MemoryPackSerializer.Deserialize<DavMultipartFile>(
            MemoryPackSerializer.Serialize(original))!;

        Assert.Equal(true, restored.Metadata.YencEncrypted);
        Assert.Equal(TransportPassword, restored.Metadata.YencTransportPassword);
    }

    [Fact]
    public void DavMultipartMeta_LegacyBlob_ReadsAsOrdinary()
    {
        var legacy = new LegacyMeta { FileParts = [] };

        var restored = MemoryPackSerializer.Deserialize<DavMultipartFile.Meta>(
            MemoryPackSerializer.Serialize(legacy))!;

        Assert.Null(restored.YencEncrypted);
        Assert.Null(restored.YencTransportPassword);
    }

    [Fact]
    public void DavRarFile_ToMeta_IsOrdinary_AndLegacyReadsOrdinary()
    {
        // Finding-4 drop: DavRarFile carries no transport-encryption context;
        // the transient meta from a legacy record is always ordinary.
        var rar = new DavRarFile
        {
            Id = Guid.NewGuid(),
            RarParts =
            [
                new DavRarFile.RarPart
                {
                    SegmentIds = ["seg0"],
                    PartSize = 100,
                    Offset = 0,
                    ByteCount = 100,
                },
            ],
        };

        var meta = rar.ToDavMultipartFileMeta();
        Assert.Null(meta.YencEncrypted);
        Assert.Null(meta.YencTransportPassword);

        var legacyBytes = MemoryPackSerializer.Serialize(new LegacyDavRarFile
        {
            Id = Guid.NewGuid(),
            RarParts = [],
        });
        var restored = MemoryPackSerializer.Deserialize<DavRarFile>(legacyBytes)!;
        Assert.Null(restored.ToDavMultipartFileMeta().YencEncrypted);
    }

    [Fact]
    public void DavRarFile_LegacyWithDroppedOrders23_RarPartsSurvive()
    {
        // F5: a blob written while DavRarFile Orders 2/3 existed (populated)
        // must deserialize into the current shape with RarParts intact; the
        // dropped fields are skipped by MemoryPack version tolerance and the
        // transient meta stays ordinary (no writer ever set them for real).
        var id = Guid.NewGuid();
        var legacyBytes = MemoryPackSerializer.Serialize(new LegacyDavRarFileWithDroppedOrders
        {
            Id = id,
            RarParts =
            [
                new DavRarFile.RarPart
                {
                    SegmentIds = ["seg0", "seg1"],
                    PartSize = 200,
                    Offset = 0,
                    ByteCount = 200,
                },
                new DavRarFile.RarPart
                {
                    SegmentIds = ["seg2"],
                    PartSize = 50,
                    Offset = 200,
                    ByteCount = 50,
                },
            ],
            YencEncrypted = true,
            YencTransportPassword = TransportPassword,
        });

        var restored = MemoryPackSerializer.Deserialize<DavRarFile>(legacyBytes)!;

        Assert.Equal(id, restored.Id);
        Assert.Equal(2, restored.RarParts.Length);
        Assert.Equal(["seg0", "seg1"], restored.RarParts[0].SegmentIds);
        Assert.Equal(200, restored.RarParts[0].PartSize);
        Assert.Equal(["seg2"], restored.RarParts[1].SegmentIds);
        Assert.Equal(200, restored.RarParts[1].Offset);
        var meta = restored.ToDavMultipartFileMeta();
        Assert.Equal(2, meta.FileParts.Length);
        Assert.Null(meta.YencEncrypted);
        Assert.Null(meta.YencTransportPassword);
    }

    [Fact]
    public void DavNzbFileBlobUpdater_Clone_CopiesContextAndProof()
    {
        // Clone is the one explicit DavNzbFile copy; DavMultipartFile.Meta clones
        // live in LazyRarResolver (WithFileParts / terminal / commit paths) and
        // copy the two fields explicitly alongside ArchivePassword.
        var source = new DavNzbFile
        {
            Id = Guid.NewGuid(),
            SegmentIds = ["seg0"],
            CorruptSegmentIndices = [0],
            YencEncrypted = true,
            YencTransportPassword = TransportPassword,
        };

        var clone = DavNzbFileBlobUpdater.Clone(source);

        Assert.Equal(true, clone.YencEncrypted);
        Assert.Equal(TransportPassword, clone.YencTransportPassword);
        Assert.Equal(source.SegmentIds, clone.SegmentIds);
        Assert.Equal(source.CorruptSegmentIndices, clone.CorruptSegmentIndices);
    }
}
