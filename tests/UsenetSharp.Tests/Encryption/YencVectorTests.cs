using System.Text;
using UsenetSharp.Encryption;

namespace UsenetSharpTest.Encryption;

/// <summary>
/// INF-06/INF-09: vendored vector conformance. Proves BouncyCastle
/// Argon2BytesGenerator (Argon2id), XChaCha20Poly1305 (24-byte nonce),
/// and FpeFf1Engine/AesEngine — or records the FF1 fallback — against
/// the standards vectors. Never encrypts fixtures with production code
/// except where a vector explicitly supplies ciphertext+tag to open.
/// </summary>
[TestFixture]
public class YencVectorTests
{
    [Test]
    public void Argon2id_Vectors_Match()
    {
        using var doc = VectorFixture.Load("argon2id.json");
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var password = VectorFixture.Str(v, "password");
            var salt = VectorFixture.Bytes(v, "salt");
            var expected = VectorFixture.Bytes(v, "expected_key");
            var actual = YencKeySchedule.DeriveMasterKeyDefault(Encoding.UTF8.GetBytes(password), salt);
            Assert.That(actual, Is.EqualTo(expected), VectorFixture.Str(v, "id"));
        }
    }

    [Test]
    public void BodyNonce_And_ControlTweak_Vectors_Match()
    {
        using var doc = VectorFixture.Load("nonce_tweak.json");
        foreach (var v in doc.RootElement.GetProperty("body_nonce_vectors").EnumerateArray())
        {
            var key = VectorFixture.Bytes(v, "key");
            var seg = VectorFixture.UInt(v, "segment_index");
            var expected = VectorFixture.Bytes(v, "expected_nonce");
            Assert.That(YencKeySchedule.DeriveBodyNonce(key, seg), Is.EqualTo(expected), VectorFixture.Str(v, "id"));
        }

        foreach (var v in doc.RootElement.GetProperty("control_tweak_vectors").EnumerateArray())
        {
            var master = VectorFixture.Bytes(v, "master_key");
            var seg = VectorFixture.UInt(v, "segment_index");
            var line = VectorFixture.UInt(v, "line_index");
            Assert.That(
                YencKeySchedule.DeriveControlKey(master),
                Is.EqualTo(VectorFixture.Bytes(v, "enc_key")),
                VectorFixture.Str(v, "id") + " enc_key");
            Assert.That(
                YencKeySchedule.DeriveControlTweak(master, seg, line),
                Is.EqualTo(VectorFixture.Bytes(v, "expected_tweak")),
                VectorFixture.Str(v, "id"));
        }
    }

    [Test]
    public void BodyEncryption_Vectors_Open_And_Aad_Matches()
    {
        using var doc = VectorFixture.Load("body_encryption.json");
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var id = VectorFixture.Str(v, "id");
            var aadObj = v.GetProperty("aad");
            var name = VectorFixture.Bytes(aadObj, "name_bytes");
            var aad = YencAad.Build(
                name,
                (uint)VectorFixture.Int(aadObj, "part_number"),
                (uint)VectorFixture.Int(aadObj, "part_begin"),
                (ulong)VectorFixture.Int(aadObj, "segment_bytes"));
            Assert.That(aad, Is.EqualTo(VectorFixture.Bytes(aadObj, "expected_aad")), id + " aad");

            // The =yencryption line in the vector must parse.
            var line = VectorFixture.Str(v, "expected_yencryption_line");
            var parsed = YencryptionLineParser.Parse(Encoding.ASCII.GetBytes(line));
            Assert.That(parsed.Salt, Is.EqualTo(VectorFixture.Bytes(v, "salt")), id);
            Assert.That(parsed.SegmentIndex, Is.EqualTo(VectorFixture.UInt(v, "segment_index")), id);
            Assert.That(parsed.Tag, Is.EqualTo(VectorFixture.Bytes(v, "expected_tag")), id);

            var key = VectorFixture.Bytes(v, "derived_key");
            Assert.That(
                YencKeySchedule.DeriveBodyNonce(key, parsed.SegmentIndex),
                Is.EqualTo(VectorFixture.Bytes(v, "derived_nonce")),
                id + " nonce");

            var plaintext = YencBodyCipher.Open(
                key,
                parsed.SegmentIndex,
                VectorFixture.Bytes(v, "expected_ciphertext"),
                parsed.Tag,
                aad);
            Assert.That(plaintext, Is.EqualTo(VectorFixture.Bytes(v, "plaintext")), id + " plaintext");
        }
    }

    [Test]
    public void ControlLine_SingleLine_Vectors_Decrypt()
    {
        using var doc = VectorFixture.Load("control_line_encryption.json");
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            if (!VectorFixture.Has(v, "plaintext_line"))
            {
                continue;
            }

            var id = VectorFixture.Str(v, "id");
            var encKey = VectorFixture.Bytes(v, "derived_enc_key");
            var tweak = VectorFixture.Bytes(v, "derived_tweak");
            var wire = VectorFixture.Bytes(v, "expected_wire");
            ReadOnlySpan<byte> ciphertext = wire;
            if (v.GetProperty("is_line_1").GetBoolean())
            {
                // Strip 20-byte bootstrap; salt/index must match.
                var bootstrap = YencControlRestorer.ParseBootstrap(wire);
                Assert.That(bootstrap.Salt, Is.EqualTo(VectorFixture.Bytes(v, "salt")), id);
                Assert.That(bootstrap.SegmentIndex, Is.EqualTo(VectorFixture.UInt(v, "segment_index")), id);
                ciphertext = wire.AsSpan(20);
            }

            var plain = YencFf1.Decrypt(encKey, tweak, ciphertext);
            Assert.That(Encoding.ASCII.GetString(plain), Is.EqualTo(VectorFixture.Str(v, "plaintext_line")), id);
        }
    }

    [Test]
    public void ControlLine_FullArticle_Vectors_Restore()
    {
        using var doc = VectorFixture.Load("control_line_encryption.json");
        var seen = 0;
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            if (!VectorFixture.Has(v, "input_lines"))
            {
                continue;
            }

            seen++;
            var id = VectorFixture.Str(v, "id");
            var password = VectorFixture.Str(v, "password");
            var salt = VectorFixture.Bytes(v, "salt");
            var seg = VectorFixture.UInt(v, "segment_index");
            var wireLines = VectorFixture.BytesList(v, "expected_wire_lines");
            var article = JoinCrlf(wireLines);
            var context = new YencEncryptionContext(password);

            // All six full-article vectors (control-vec-07..12) are combined-mode
            // valid at the control-line layer: Restore must succeed and reproduce
            // input_lines exactly. The vendored file note ("data lines are opaque
            // filler, their =yencryption tags are not authenticated") means only
            // that Restore does not authenticate the body tag here — it does not
            // make any of these vectors combined-mode-invalid, so there is no
            // fail-closed branch to accept. (Single-line vectors control-vec-01..06
            // have no input_lines and are exercised by
            // ControlLine_SingleLine_Vectors_Decrypt instead.)
            var restored = YencControlRestorer.Restore(context, article);
            var restoredLines = SplitContents(restored.RestoredBlock);
            var expected = new List<string>();
            foreach (var l in v.GetProperty("input_lines").EnumerateArray())
            {
                expected.Add(l.GetString()!);
            }

            Assert.That(restoredLines, Is.EqualTo(expected), id);
            Assert.That(restored.Salt, Is.EqualTo(salt), id);
            Assert.That(restored.SegmentIndex, Is.EqualTo(seg), id);
        }

        Assert.That(seen, Is.EqualTo(6), "expected the six full-article vectors control-vec-07..12");
    }

    [Test]
    public void IndexAllocation_Vectors()
    {
        using var doc = VectorFixture.Load("index_allocation.json");
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var candidate = VectorFixture.UInt(v, "candidate_index");
            var expected = VectorFixture.UInt(v, "expected_assigned_index");
            // Next permitted: skip any index whose BE bytes contain 0x0A/0x0D.
            var assigned = candidate;
            while (ContainsForbidden(assigned))
            {
                assigned++;
            }

            Assert.That(assigned, Is.EqualTo(expected), VectorFixture.Str(v, "id"));
            var be = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(be, assigned);
            Assert.That(be, Is.EqualTo(VectorFixture.Bytes(v, "expected_index")), VectorFixture.Str(v, "id"));
        }
    }

    [Test]
    public void Malformed_Yencryption_Lines_Rejected_Before_Kdf()
    {
        using var doc = VectorFixture.Load("malformed_inputs.json");
        var counting = 0;
        var context = YencEncryptionContext.CreateForTest(
            "public-conformance-vector-key-2026",
            (pwd, salt) =>
            {
                counting++;
                return new byte[32];
            });
        _ = context; // Parser path must not need a context/KDF at all.

        var seen = 0;
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            if (!VectorFixture.Has(v, "input_line"))
            {
                continue;
            }

            seen++;
            var line = VectorFixture.Str(v, "input_line");
            Assert.Throws<YencEncryptionFailoverException>(
                () => YencryptionLineParser.Parse(Encoding.ASCII.GetBytes(line)),
                VectorFixture.Str(v, "id"));
        }

        Assert.That(seen, Is.GreaterThanOrEqualTo(20));
        Assert.That(counting, Is.EqualTo(0), "grammar rejection must happen before KDF");
    }

    [Test]
    public void Malformed_AuthFailures_Release_Zero_Plaintext()
    {
        using var doc = VectorFixture.Load("malformed_inputs.json");
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            if (VectorFixture.Str(v, "category") != "auth_failure")
            {
                continue;
            }

            var id = VectorFixture.Str(v, "id");
            var password = VectorFixture.Str(v, "password");
            var salt = VectorFixture.Bytes(v, "salt");
            var seg = VectorFixture.UInt(v, "segment_index");
            var aad = VectorFixture.Bytes(v, "aad");
            byte[] ciphertext;
            byte[] tag;
            if (VectorFixture.Has(v, "tampered_ciphertext"))
            {
                ciphertext = VectorFixture.Bytes(v, "tampered_ciphertext");
                tag = VectorFixture.Bytes(v, "tag");
            }
            else if (VectorFixture.Has(v, "tampered_tag"))
            {
                ciphertext = VectorFixture.Bytes(v, "ciphertext");
                tag = VectorFixture.Bytes(v, "tampered_tag");
            }
            else
            {
                ciphertext = VectorFixture.Bytes(v, "ciphertext");
                tag = VectorFixture.Bytes(v, "tag");
            }

            // Derivation uses the vector's own salt; wrong-password vectors differ only by password.
            var context = new YencEncryptionContext(password);
            Assert.Throws<YencEncryptionFailoverException>(
                () =>
                {
                    var master = context.GetMasterKey(salt);
                    YencBodyCipher.Open(master, seg, ciphertext, tag, aad);
                },
                id);
        }
    }

    [Test]
    public void Malformed_ControlSyntax_Bootstrap_Rejected()
    {
        using var doc = VectorFixture.Load("malformed_inputs.json");
        var exercised = 0;
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var id = VectorFixture.Str(v, "id");
            // Real vendored keys are tampered_salt_bytes / line1_bytes / line_bytes
            // (VectorFixture.Bytes appends "_bytes"); the previous dead names
            // (tampered_salt / line1 / line) matched nothing, so no branch ran.
            if (VectorFixture.Has(v, "tampered_salt_bytes"))
            {
                exercised++;
                var line1 = new byte[22];
                VectorFixture.Bytes(v, "tampered_salt").CopyTo(line1, 0);
                // Bytes 16..19: a valid segment index (1); bytes 20..21: the
                // minimum 2-byte FF1 payload ParseBootstrap requires.
                line1[19] = 1;
                line1[20] = (byte)'=';
                line1[21] = (byte)'=';
                Assert.Throws<YencEncryptionFailoverException>(() => YencControlRestorer.ParseBootstrap(line1), id);
            }
            else if (VectorFixture.Has(v, "line1_bytes"))
            {
                exercised++;
                var line1 = VectorFixture.Bytes(v, "line1");
                Assert.Throws<YencEncryptionFailoverException>(() => YencControlRestorer.ParseBootstrap(line1), id);
            }
            else if (VectorFixture.Has(v, "line_bytes"))
            {
                exercised++;
                var line = VectorFixture.Bytes(v, "line");
                var tweak = new byte[8];
                Assert.Throws<YencEncryptionFailoverException>(() => YencFf1.Decrypt(new byte[32], tweak, line), id);
            }
        }

        // control-syntax-01..06 and 08..11 (10 vectors; 07 is a wrong-password
        // description with no line bytes and is not exercised here).
        Assert.That(exercised, Is.EqualTo(10), "every control-syntax line vector must exercise production code");
    }

    [Test]
    public void Malformed_DualMismatch_Rejected()
    {
        // Fixture-location choice: the dual-mismatch wire articles were generated
        // under tests/NzbWebDAV.Tests/TestFixtures/EncryptedArticles/, but the
        // production Restore under test lives in UsenetSharp and this suite owns
        // the vector tests. The two .bin files are therefore also vendored inside
        // this project at TestFixtures/EncryptedArticles/ (see README.md there;
        // submodule self-containment only forbids leaving infinidysk/). Unlike
        // the previous fixture-arithmetic-only body, this exercises production
        // Restore on real wire articles whose Line 1 bootstrap disagrees with
        // the restored =yencryption line (salt in tamper-dual-salt.bin, index
        // in tamper-dual-index.bin; manifest password/salt as in INF-05).
        var context = new YencEncryptionContext("public-conformance-vector-key-2026");
        var exercised = 0;
        foreach (var file in new[] { "tamper-dual-salt.bin", "tamper-dual-index.bin" })
        {
            exercised++;
            var article = LoadEncryptedArticle(file);
            Assert.Throws<YencEncryptionFailoverException>(
                () => YencControlRestorer.Restore(context, article),
                file);
        }

        Assert.That(exercised, Is.EqualTo(2));
    }

    [Test]
    public void Placement_WrongPosition_Articles_Rejected()
    {
        // placement-01..04 (see gen provenance in the NzbWebDAV.Tests manifest
        // directory; copies vendored alongside the dual fixtures above):
        // =yencryption at the wrong fixed position or contradictory
        // =ybegin/=ypart framing. Production Restore must reject each as
        // provider-failover before any plaintext is released.
        var context = new YencEncryptionContext("public-conformance-vector-key-2026");
        var exercised = 0;
        foreach (var file in new[]
                 {
                     "placement-01-single-part-line-three.bin",
                     "placement-02-multipart-after-data.bin",
                     "placement-03-ypart-without-part.bin",
                     "placement-04-yencryption-line2-with-part.bin",
                 })
        {
            exercised++;
            var article = LoadEncryptedArticle(file);
            Assert.Throws<YencEncryptionFailoverException>(
                () => YencControlRestorer.Restore(context, article),
                file);
        }

        Assert.That(exercised, Is.EqualTo(4));
    }

    [Test]
    public void Metadata_Tier_Vectors_Are_LocalFatal()
    {
        // Honest scope: the metadata_validation vectors (metadata-01..03) pin
        // nothing at this layer — NZB metadata/provenance and missing-password
        // ingest handling are Phase 2 (INF-10) scope, and no production code
        // under test here consumes those vectors. What this test does pin is
        // the one local-fatal behaviour that does exist in this module today:
        // constructing a context with a missing password fails locally
        // (metadata-03's tier), before any fetch/KDF of article bytes.
        Assert.Throws<YencEncryptionLocalException>(() => new YencEncryptionContext(""));
        Assert.Throws<YencEncryptionLocalException>(() => new YencEncryptionContext(null!));
    }

    private static byte[] LoadEncryptedArticle(string fileName)
    {
        var path = Path.Join(AppContext.BaseDirectory, "TestFixtures", "EncryptedArticles", fileName);
        Assert.That(File.Exists(path), Is.True, $"Missing vendored fixture {path}");
        return File.ReadAllBytes(path);
    }

    private static bool ContainsForbidden(uint v)
    {
        var be = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(be, v);
        return be.Contains((byte)0x0A) || be.Contains((byte)0x0D);
    }

    private static byte[] JoinCrlf(byte[][] lines)
    {
        using var ms = new MemoryStream();
        foreach (var l in lines)
        {
            ms.Write(l);
            ms.Write("\r\n"u8);
        }

        return ms.ToArray();
    }

    private static List<string> SplitContents(byte[] block)
    {
        var lines = YencControlRestorer.SplitLinesPreservingEndings(block);
        var result = new List<string>();
        foreach (var l in lines)
        {
            var (content, _) = YencControlRestorer.SplitEnding(l);
            result.Add(Encoding.ASCII.GetString(content));
        }

        return result;
    }
}
