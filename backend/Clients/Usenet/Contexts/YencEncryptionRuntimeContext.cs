namespace NzbWebDAV.Clients.Usenet.Contexts;

/// <summary>
/// Ambient per-operation yEnc transport-encryption context (INF-14, plan
/// §4.3.1). Mirrors the <see cref="YencFileValidationContext"/> AsyncLocal
/// pattern: stream/queue call sites install the job's context with
/// <see cref="Begin"/>; <see cref="BaseNntpClient"/> reads
/// <see cref="CurrentRuntimeContext"/> at each decoded-body entry point and
/// hands the snapshot to UsenetSharp via
/// <see cref="UsenetSharp.Clients.UsenetClientOptions.YencEncryptionProvider"/>.
/// Clients are pooled — the password is never stored on a client instance;
/// it is evaluated per operation from this AsyncLocal. No ambient context
/// means ordinary decoding, byte-identical to upstream.
/// </summary>
internal sealed class YencEncryptionRuntimeContext : IDisposable
{
    private static readonly AsyncLocal<YencEncryptionRuntimeContext?> Active = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Usage", "CA2213:Disposable fields should be disposed",
        Justification = "The borrowed parent scope owns its disposal and must be restored, not disposed.")]
    private readonly YencEncryptionRuntimeContext? _previous = Active.Value;
    private readonly Lazy<UsenetSharp.Encryption.YencEncryptionContext?> _runtime;

    private readonly bool _installed;

    private YencEncryptionRuntimeContext(string? transportPassword)
    {
        // One runtime context per ambient scope so its single-flight
        // master-key cache is shared by every segment of the job/stream.
        // The Clients layer takes only the password primitive — never the
        // Queue-layer context type (architecture boundary).
        // A null/empty password is the ordinary path and a TRUE no-op:
        // nothing is installed, so IsActive-gated cache behaviour of
        // ordinary traffic stays byte-identical to upstream.
        _runtime = new Lazy<UsenetSharp.Encryption.YencEncryptionContext?>(() =>
            string.IsNullOrEmpty(transportPassword)
                ? null
                : new UsenetSharp.Encryption.YencEncryptionContext(transportPassword));
        if (string.IsNullOrEmpty(transportPassword)) return;
        Active.Value = this;
        _installed = true;
    }

    // Re-activation of a captured runtime (see Capture/Activate): no new
    // derivation, the same context instance and KDF cache are reused.
    // A null runtime is a TRUE no-op: it neither installs nor clears an
    // ambient scope, so ordinary traffic's cache/decoding behaviour (gated
    // on IsActive) is byte-identical to upstream — an Activate(null) inside
    // a caller's real scope must not hide that scope either.
    private YencEncryptionRuntimeContext(UsenetSharp.Encryption.YencEncryptionContext? runtime)
    {
        _runtime = new Lazy<UsenetSharp.Encryption.YencEncryptionContext?>(() => runtime);
        if (runtime is null) return;
        Active.Value = this;
        _installed = true;
    }

    public static bool IsActive => Active.Value is not null;

    /// <summary>
    /// The runtime context of the ambient scope, without installing one. Stream
    /// constructors capture this when they must keep serving an encrypted read
    /// after the caller's `using` scope has been disposed (lazy async
    /// enumeration, background producers): they re-enter with
    /// <see cref="Activate"/> for each read so the shared single-flight KDF
    /// cache survives while the ambient scope itself does not leak.
    /// </summary>
    public static UsenetSharp.Encryption.YencEncryptionContext? Capture() => CurrentRuntimeContext;

    /// <summary>
    /// Re-enters a scope holding exactly <paramref name="runtime"/>
    /// (from <see cref="Capture"/>) so a stream read runs with the same
    /// master-key cache even outside the original construction scope. A null
    /// runtime reproduces the ordinary no-scope path exactly.
    /// </summary>
    public static IDisposable Activate(UsenetSharp.Encryption.YencEncryptionContext? runtime) =>
        new YencEncryptionRuntimeContext(runtime);

    /// <summary>
    /// The persisted per-file context as an ambient scope (INF-21): encrypted
    /// blobs with no resolvable password fail closed — a stream built from an
    /// encrypted blob without a password must never silently serve
    /// ciphertext as content. Ordinary files (flag unset) get an inert
    /// scope whose runtime is null: the decoder behaves byte-identically.
    /// </summary>
    public static IDisposable BeginForFile(bool? encrypted, string? transportPassword)
    {
        if (encrypted == true && string.IsNullOrEmpty(transportPassword))
        {
            throw new UsenetSharp.Encryption.YencEncryptionLocalException(
                "MISSING_PASSWORD: encrypted file blob carries no transport password");
        }
        return Begin(encrypted == true ? transportPassword : null);
    }

    /// <summary>
    /// The runtime context a file's persisted fields resolve to, without
    /// installing a scope. Null for ordinary files. Throws (fail closed) for
    /// an encrypted blob with no password — callers capture this at stream
    /// construction so the failure surfaces before any byte is read.
    /// </summary>
    public static UsenetSharp.Encryption.YencEncryptionContext? CaptureForFile(
        bool? encrypted, string? transportPassword)
    {
        if (encrypted != true) return null;
        if (string.IsNullOrEmpty(transportPassword))
        {
            throw new UsenetSharp.Encryption.YencEncryptionLocalException(
                "MISSING_PASSWORD: encrypted file blob carries no transport password");
        }
        return new UsenetSharp.Encryption.YencEncryptionContext(transportPassword);
    }

    /// <summary>
    /// Installs the ambient scope for one job/stream. Takes only the
    /// resolved transport password (null for ordinary NZBs) so this Clients
    /// type never references Queue-layer types; call sites pass
    /// <c>context is { Encrypted: true } ? context.TransportPassword : null</c>.
    /// </summary>
    public static IDisposable Begin(string? transportPassword) =>
        new YencEncryptionRuntimeContext(transportPassword);


    /// <summary>
    /// The runtime context for the current async flow, or null when no
    /// encryption scope is active. Invoked once per decoded body by the
    /// UsenetSharp provider hook; pooled clients never cache the result.
    /// </summary>
    public static UsenetSharp.Encryption.YencEncryptionContext? CurrentRuntimeContext =>
        Active.Value?._runtime.Value;

    public void Dispose()
    {
        if (_installed) Active.Value = _previous;
    }
}
