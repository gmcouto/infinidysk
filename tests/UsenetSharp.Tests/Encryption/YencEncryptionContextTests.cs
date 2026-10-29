using System.Text;
using UsenetSharp.Encryption;

namespace UsenetSharpTest.Encryption;

/// <summary>INF-08: single-flight master-key cache, owned by the context instance.</summary>
[TestFixture]
public class YencEncryptionContextTests
{
    [Test]
    public async Task Concurrent_Gets_For_One_Salt_Derive_Exactly_Once()
    {
        var derivations = 0;
        var context = YencEncryptionContext.CreateForTest(
            "pw",
            (pwd, salt) =>
            {
                Interlocked.Increment(ref derivations);
                Thread.Sleep(20);
                return Enumerable.Repeat((byte)7, 32).ToArray();
            });
        var salt = new byte[16];

        var tasks = Enumerable.Range(0, 16)
            .Select(_ => context.GetMasterKeyAsync(salt))
            .ToArray();
        var keys = await Task.WhenAll(tasks);

        Assert.That(derivations, Is.EqualTo(1));
        Assert.That(keys.All(k => k.AsSpan().SequenceEqual(keys[0])), Is.True);
    }

    [Test]
    public async Task Different_Salts_Derive_Separately_Never_Per_Segment()
    {
        var derivations = 0;
        var context = YencEncryptionContext.CreateForTest(
            "pw",
            (pwd, salt) =>
            {
                Interlocked.Increment(ref derivations);
                return new byte[32];
            });

        var saltA = new byte[16];
        var saltB = new byte[16];
        saltB[0] = 1;

        // Many segment-index derivations must not re-run Argon2id: nonce/tweak are HMAC only.
        _ = await context.GetMasterKeyAsync(saltA);
        for (uint seg = 1; seg <= 8; seg++)
        {
            var master = await context.GetMasterKeyAsync(saltA);
            _ = YencKeySchedule.DeriveBodyNonce(master, seg);
            _ = YencKeySchedule.DeriveControlTweak(master, seg, 1);
        }

        _ = await context.GetMasterKeyAsync(saltB);
        Assert.That(derivations, Is.EqualTo(2));
    }

    [Test]
    public void Separate_Contexts_Do_Not_Share_Cache()
    {
        var derivations = 0;
        Func<byte[], byte[], byte[]> kdf = (pwd, salt) =>
        {
            Interlocked.Increment(ref derivations);
            return new byte[32];
        };
        var a = YencEncryptionContext.CreateForTest("pw", kdf);
        var b = YencEncryptionContext.CreateForTest("pw", kdf);
        var salt = new byte[16];
        _ = a.GetMasterKey(salt);
        _ = b.GetMasterKey(salt);
        Assert.That(derivations, Is.EqualTo(2), "cache lifetime is the context instance, never process-global");
        _ = Encoding.UTF8; // keep using directive meaningful in Release analyzers
    }
}
