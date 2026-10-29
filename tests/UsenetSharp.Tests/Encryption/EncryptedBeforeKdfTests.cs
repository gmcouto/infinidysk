using UsenetSharp.Encryption;

namespace UsenetSharpTest.Encryption;

/// <summary>
/// INF-20: malformed inputs are rejected before any Argon2id work, and one
/// salt derives exactly once across segments (single-flight, INF-08).
/// </summary>
[TestFixture]
public class EncryptedBeforeKdfTests
{
    private const string Password = "public-conformance-vector-key-2026";

    // Vendored inside this test project (see TestFixtures/EncryptedArticles/README.md).
    private static string FixtureDir => Path.Join(
        AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles");

    private static byte[] Load(string name) => File.ReadAllBytes(Path.Join(FixtureDir, name));

    [Test]
    public void ZeroSegmentIndex_Rejected_BeforeKdf()
    {
        var derivations = 0;
        var context = YencEncryptionContext.CreateCountingForTest(
            Password, () => Interlocked.Increment(ref derivations));
        var article = Load("article-single.bin");

        // Zero the Line-1 segment index (bytes 16..19): ParseBootstrap
        // rejects index 0 before the master key is ever derived.
        var tampered = article.ToArray();
        tampered[16] = 0;
        tampered[17] = 0;
        tampered[18] = 0;
        tampered[19] = 0;

        Assert.Throws<YencEncryptionFailoverException>(
            () => YencControlRestorer.Restore(context, tampered));
        Assert.That(derivations, Is.EqualTo(0));
    }

    [Test]
    public void TruncatedLine1_Rejected_BeforeKdf()
    {
        var derivations = 0;
        var context = YencEncryptionContext.CreateCountingForTest(
            Password, () => Interlocked.Increment(ref derivations));

        Assert.Throws<YencEncryptionFailoverException>(
            () => YencControlRestorer.Restore(context, Load("article-single.bin").AsSpan(0, 10)));
        Assert.That(derivations, Is.EqualTo(0));
    }

    [Test]
    public void MalformedYencryptionGrammar_Rejected_BeforeKdf()
    {
        // The plain-line grammar path validates without any context/KDF.
        var line = System.Text.Encoding.ASCII.GetBytes(
            "=yencryption cipher=XChaCha20-Poly1305 salt=xyz index=00000001 tag=abcd");
        Assert.Throws<YencEncryptionFailoverException>(() => YencryptionLineParser.Parse(line));
    }

    [Test]
    public void SameSalt_MultipleSegments_DeriveExactlyOnce()
    {
        var derivations = 0;
        var context = YencEncryptionContext.CreateCountingForTest(
            Password, () => Interlocked.Increment(ref derivations));

        _ = EncryptedYencAssembler.OpenArticle(context, Load("article-single.bin"));
        _ = EncryptedYencAssembler.OpenArticle(context, Load("article-part1.bin"));
        _ = EncryptedYencAssembler.OpenArticle(context, Load("article-part2.bin"));

        Assert.That(derivations, Is.EqualTo(1));
    }
}
