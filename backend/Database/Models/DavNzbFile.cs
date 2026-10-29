using System.ComponentModel.DataAnnotations.Schema;
using MemoryPack;
using NzbWebDAV.Models;

namespace NzbWebDAV.Database.Models;

[MemoryPackable(GenerateType.VersionTolerant)]
public partial class DavNzbFile
{
    [MemoryPackOrder(0)]
    public Guid Id { get; set; } // foreign key to DavItem.Id

    [MemoryPackOrder(1)]
    public string[] SegmentIds { get; set; } = [];

    [NotMapped]
    [MemoryPackOrder(2)]
    public LongRange[]? SegmentByteRanges { get; set; }

    /// <summary>
    /// Per-segment alternate MessageIds aligned with <see cref="SegmentIds"/>.
    /// Null on blobs written before this field existed.
    /// Blob/MemoryPack only — not an EF column (nested string[][] is unsupported).
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(3)]
    public string[][]? SegmentFallbackIds { get; set; }

    /// <summary>
    /// Segment indices confirmed missing on all providers and all fallback MessageIds
    /// by a full-coverage health sweep (ascending, absolute). Null = no degraded record.
    /// Blob/MemoryPack only — not an EF column.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(4)]
    public int[]? MissingSegmentIndices { get; set; }

    /// <summary>
    /// The probed media container class (MediaContainerClass as byte), persisted after the
    /// first successful head probe so a file is probed at most once. Null = never probed.
    /// Blob/MemoryPack only — not an EF column.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(5)]
    public byte? ContainerClass { get; set; }

    /// <summary>
    /// Exclusive end offset of the moov atom for a probed fast-start MP4. Null = not probed
    /// or not applicable (non-MP4, moov-at-end, fragmented, or an insane declared size).
    /// Blob/MemoryPack only — not an EF column.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(6)]
    public long? CriticalHeadEndExclusive { get; set; }

    /// <summary>
    /// Absolute segment indices confirmed corrupt on all providers during streaming
    /// (ascending). Null = no streaming-corruption record.
    /// Blob/MemoryPack only — not an EF column. VersionTolerant / additive — no migration.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(7)]
    public int[]? CorruptSegmentIndices { get; set; }

    /// <summary>
    /// True only when <see cref="SegmentByteRanges"/> came from complete or
    /// middle-segment-validated yEnc geometry. Null on legacy blobs, which must
    /// use header-probed seeking rather than trusting structurally valid inference.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(8)]
    public bool? SegmentByteRangesTrusted { get; set; }

    [NotMapped]
    [MemoryPackOrder(9)]
    public Par2FileProof? VerificationProof { get; set; }

    /// <summary>
    /// True when this file's articles are yEnc transport-encrypted (Body Standard §8,
    /// v1.2 combined mode). Null/false on legacy blobs = ordinary, untouched behaviour.
    /// Blob/MemoryPack only — not an EF column. VersionTolerant / additive — no migration.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(10)]
    public bool? YencEncrypted { get; set; }

    /// <summary>
    /// Resolved transport password for <see cref="YencEncrypted"/> (filename password
    /// wins over NZB meta). Persisted resolved so WebDAV reads do not re-derive it
    /// from a queue-item filename. Never logged. Blob/MemoryPack only.
    /// </summary>
    [NotMapped]
    [MemoryPackOrder(11)]
    public string? YencTransportPassword { get; set; }

    // navigation helpers
    [MemoryPackIgnore]
    public DavItem? DavItem { get; set; }
}
