using System.ComponentModel.DataAnnotations.Schema;
using MemoryPack;
using NzbWebDAV.Models;

namespace NzbWebDAV.Database.Models;

[MemoryPackable(GenerateType.VersionTolerant)]
public partial class DavRarFile
{
    [MemoryPackOrder(0)]
    public Guid Id { get; set; } // foreign key to DavItem.Id

    [MemoryPackOrder(1)]
    public RarPart[] RarParts { get; set; } = [];

    // INF-21 / Finding-4 (writer-or-drop): the Orders 2/3
    // YencEncrypted/YencTransportPassword fields introduced in Phase 2 are
    // DROPPED. They had no writer: every current import mounts RAR content
    // as DavMultipartFile (RarAggregator / LazyRarProcessor), and no code
    // path constructs a DavRarFile — the record is read-only legacy from
    // pre-blob-store installs. A legacy encrypted DavRarFile could only be
    // mis-served anyway: nothing wrote its fields, so any supposedly
    // encrypted legacy record reads as ordinary. Removing the fields keeps
    // one source of truth (DavMultipartFile.Meta Orders 7/8); old blobs
    // written with Orders 2/3 are tolerated by MemoryPack version tolerance
    // (unknown trailing fields are skipped on deserialize).

    // navigation helpers
    [MemoryPackIgnore]
    public DavItem? DavItem { get; set; }

    [MemoryPackable(GenerateType.VersionTolerant)]
    public partial class RarPart
    {
        [MemoryPackOrder(0)]
        public string[] SegmentIds { get; set; } = [];

        [MemoryPackOrder(1)]
        public long PartSize { get; set; }

        [MemoryPackOrder(2)]
        public long Offset { get; set; }

        [MemoryPackOrder(3)]
        public long ByteCount { get; set; }

        [MemoryPackOrder(4)]
        public LongRange[]? SegmentByteRanges { get; set; }

        [MemoryPackOrder(5)]
        public string[][]? SegmentFallbackIds { get; set; }

        // Null on legacy blobs. Only true permits arithmetic segment seeking.
        [MemoryPackOrder(6)]
        public bool? SegmentByteRangesTrusted { get; set; }
    }

    public DavMultipartFile.Meta ToDavMultipartFileMeta()
    {
        // Legacy DavRarFile records predate transport encryption and carry
        // no context (Finding-4 drop above); the transient meta is ordinary.
        return new DavMultipartFile.Meta
        {
            FileParts = RarParts.Select(x => new DavMultipartFile.FilePart()
            {
                SegmentIds = x.SegmentIds,
                SegmentIdByteRange = LongRange.FromStartAndSize(
                    0,
                    Math.Max(x.PartSize, checked(x.Offset + x.ByteCount))),
                FilePartByteRange = LongRange.FromStartAndSize(x.Offset, x.ByteCount),
                SegmentByteRanges = x.SegmentByteRanges,
                SegmentFallbackIds = x.SegmentFallbackIds,
                SegmentByteRangesTrusted = x.SegmentByteRangesTrusted,
            }).ToArray()
        };
    }
}
