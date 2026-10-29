using System.Text.Json;

namespace UsenetSharpTest.Encryption;

/// <summary>
/// Loads vendored conformance vectors from inside this submodule
/// (tests/UsenetSharp.Tests/TestFixtures, copied to output).
/// Binary fields are JSON arrays of byte values under *_bytes keys.
/// </summary>
internal static class VectorFixture
{
    public static JsonDocument Load(string fileName)
    {
        var path = Path.Join(AppContext.BaseDirectory, "TestFixtures", fileName);
        Assert.That(File.Exists(path), Is.True, $"Missing vendored fixture {path}");
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    public static byte[] Bytes(JsonElement parent, string key)
    {
        // key is e.g. "salt" -> "salt_bytes"; nested AAD name uses name_bytes_bytes.
        JsonElement arr;
        if (parent.TryGetProperty(key + "_bytes", out var direct) && direct.ValueKind == JsonValueKind.Array)
        {
            arr = direct;
        }
        else if (parent.TryGetProperty(key + "_bytes_bytes", out var nested) && nested.ValueKind == JsonValueKind.Array)
        {
            arr = nested;
        }
        else
        {
            return [];
        }

        var result = new byte[arr.GetArrayLength()];
        var i = 0;
        foreach (var item in arr.EnumerateArray())
        {
            result[i++] = (byte)item.GetInt32();
        }

        return result;
    }

    public static byte[][] BytesList(JsonElement parent, string key)
    {
        parent.TryGetProperty(key + "_bytes", out var arr);
        var result = new byte[arr.GetArrayLength()][];
        var i = 0;
        foreach (var item in arr.EnumerateArray())
        {
            var inner = new byte[item.GetArrayLength()];
            var j = 0;
            foreach (var b in item.EnumerateArray())
            {
                inner[j++] = (byte)b.GetInt32();
            }

            result[i++] = inner;
        }

        return result;
    }

    public static string Str(JsonElement e, string key) => e.GetProperty(key).GetString()!;

    public static int Int(JsonElement e, string key) => e.GetProperty(key).GetInt32();

    public static uint UInt(JsonElement e, string key) => (uint)e.GetProperty(key).GetInt64();

    public static bool Has(JsonElement e, string key) => e.TryGetProperty(key, out var v) && v.ValueKind != JsonValueKind.Null;
}
