using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace UsenetSharp.Encryption;

/// <summary>
/// Key schedule (Body §4 / Control §4, plan §4.4): Argon2id master key,
/// HMAC-SHA256 body nonce / control key / control tweak derivations.
/// </summary>
public static class YencKeySchedule
{
    /// <summary>
    /// Default KDF: Argon2id (BouncyCastle <see cref="Argon2BytesGenerator"/>),
    /// time=1, memory=65536 KiB, threads=4, version=0x13, 32-byte output,
    /// password as UTF-8 with no normalization. Local failures are local-fatal.
    /// </summary>
    public static byte[] DeriveMasterKeyDefault(byte[] passwordUtf8, byte[] salt)
    {
        try
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithIterations(1)
                .WithMemoryAsKB(65536)
                .WithParallelism(4)
                .WithSalt(salt)
                .Build();
            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);
            var output = new byte[32];
            generator.GenerateBytes(passwordUtf8, output);
            return output;
        }
        catch (Exception ex) when (ex is not YencEncryptionLocalException)
        {
            throw new YencEncryptionLocalException("Argon2id key derivation failed", ex);
        }
    }

    public static byte[] DeriveBodyNonce(ReadOnlySpan<byte> masterKey, uint segmentIndex)
    {
        Span<byte> message = stackalloc byte[19];
        "yenc-body nonce"u8.CopyTo(message);
        BinaryPrimitives.WriteUInt32BigEndian(message[15..], segmentIndex);
        var hash = HMACSHA256.HashData(masterKey, message);
        return hash[..24];
    }

    public static byte[] DeriveControlKey(ReadOnlySpan<byte> masterKey)
    {
        return HMACSHA256.HashData(masterKey, "yenc-control key"u8);
    }

    public static byte[] DeriveControlTweak(ReadOnlySpan<byte> masterKey, uint segmentIndex, uint lineIndex)
    {
        Span<byte> message = stackalloc byte[26];
        "yenc-control tweak"u8.CopyTo(message);
        BinaryPrimitives.WriteUInt32BigEndian(message[18..], segmentIndex);
        BinaryPrimitives.WriteUInt32BigEndian(message[22..], lineIndex);
        var hash = HMACSHA256.HashData(masterKey, message);
        return hash[..8];
    }
}

/// <summary>
/// Per-context single-flight master-key cache (INF-08, plan §4.4).
/// Concurrent callers for one salt collapse to one KDF run; lifetime is
/// this instance, never static/process-global; keys are never persisted.
/// The injectable KDF delegate exists so tests can count derivations.
/// </summary>
public sealed class YencEncryptionContext
{
    private readonly byte[] _passwordUtf8;
    private readonly Func<byte[], byte[], byte[]> _kdf;
    private readonly Dictionary<string, Lazy<Task<byte[]>>> _cache = new();
    private readonly object _gate = new();

    public YencEncryptionContext(string password)
        : this(password, null)
    {
    }

    internal YencEncryptionContext(string? password, Func<byte[], byte[], byte[]>? kdf)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new YencEncryptionLocalException("MISSING_PASSWORD: no password supplied for yEnc-encrypted article");
        }

        _passwordUtf8 = Encoding.UTF8.GetBytes(password);
        _kdf = kdf ?? YencKeySchedule.DeriveMasterKeyDefault;
    }

    // Test seam: counting KDF stub.
    internal static YencEncryptionContext CreateForTest(string password, Func<byte[], byte[], byte[]> kdf) =>
        new(password, kdf);

    /// <summary>
    /// Test seam: wraps the real KDF and invokes <paramref name="onDerive"/> on
    /// each actual (cache-miss) derivation, so tests can prove rejection
    /// happens before any KDF and that one salt derives exactly once.
    /// </summary>
    internal static YencEncryptionContext CreateCountingForTest(
        string password, Action onDerive) =>
        new(password, (pwd, salt) =>
        {
            onDerive();
            return YencKeySchedule.DeriveMasterKeyDefault(pwd, salt);
        });

    /// <summary>
    /// Gets (deriving at most once per salt for this context) the master key.
    /// The returned array is owned by the cache; callers must not mutate/zero it.
    /// </summary>
    public async Task<byte[]> GetMasterKeyAsync(ReadOnlyMemory<byte> salt)
    {
        var key = Convert.ToHexString(salt.Span);
        Lazy<Task<byte[]>> lazy;
        lock (_gate)
        {
            if (!_cache.TryGetValue(key, out var existing))
            {
                var saltCopy = salt.ToArray();
                lazy = new Lazy<Task<byte[]>>(
                    () => Task.Run(() => _kdf(_passwordUtf8, saltCopy)),
                    LazyThreadSafetyMode.ExecutionAndPublication);
                _cache[key] = lazy;
            }
            else
            {
                lazy = existing;
            }
        }

        try
        {
            return await lazy.Value.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not YencEncryptionLocalException)
        {
            throw new YencEncryptionLocalException("Argon2id key derivation failed", ex);
        }
    }

    public byte[] GetMasterKey(ReadOnlySpan<byte> salt) =>
        GetMasterKeyAsync(salt.ToArray()).GetAwaiter().GetResult();
}


