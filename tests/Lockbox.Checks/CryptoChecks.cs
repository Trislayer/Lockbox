using System.Diagnostics;
using System.Text;
using Lockbox.Core.Crypto;

namespace Lockbox.Checks;

/// <summary>
/// The two primitives Lockbox implements itself. Each is pinned by a published test vector
/// and, where the tool exists, by agreement with an independent implementation.
/// </summary>
internal static class CryptoChecks
{
    public static void Run()
    {
        Blake2bVectors();
        Blake2bAgainstPython();
        Argon2idVector();
        Argon2idAgainstOpenSsl();
    }

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

    private static byte[] Blake(byte[] data, int length)
    {
        var output = new byte[length];
        Blake2b.Hash(data, output);
        return output;
    }

    private static void Blake2bVectors()
    {
        Checks.Section("BLAKE2b - RFC 7693 vectors");
        Checks.Equal(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            Hex(Blake("abc"u8.ToArray(), 64)), "BLAKE2b-512(\"abc\") matches RFC 7693 Appendix A");
        Checks.Equal(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            Hex(Blake([], 64)), "BLAKE2b-512 of the empty string");

        // Incremental updates split at awkward places must equal the one-shot hash.
        var data = Enumerable.Range(0, 1000).Select(i => (byte)i).ToArray();
        var whole = Blake(data, 64);
        var split = new Blake2b(64);
        split.Update(data.AsSpan(0, 1));
        split.Update(data.AsSpan(1, 127));
        split.Update(data.AsSpan(128, 128));
        split.Update(data.AsSpan(256));
        var splitOut = new byte[64];
        split.Final(splitOut);
        Checks.Is(whole.AsSpan().SequenceEqual(splitOut), "incremental updates across block boundaries equal one-shot");
    }

    private static void Blake2bAgainstPython()
    {
        Checks.Section("BLAKE2b - agreement with Python hashlib");
        var lengths = new[] { 0, 1, 64, 127, 128, 129, 255, 256, 257, 1000 };
        var digestSizes = new[] { 1, 20, 32, 48, 64 };
        var script = "import hashlib\n" + string.Join("\n", lengths.SelectMany(n => digestSizes.Select(d =>
            $"print(hashlib.blake2b(bytes(i % 256 for i in range({n})), digest_size={d}).hexdigest())")));
        var output = Checks.Run("python", "-I", "-c", script) ?? Checks.Run("python3", "-I", "-c", script);
        if (output is null)
        {
            Checks.Skip("python is not on PATH");
            return;
        }

        var expected = output.Split('\n', StringSplitOptions.TrimEntries);
        var k = 0;
        var mismatches = 0;
        foreach (var n in lengths)
        foreach (var d in digestSizes)
        {
            var data = Enumerable.Range(0, n).Select(i => (byte)(i % 256)).ToArray();
            if (Hex(Blake(data, d)) != expected[k++]) mismatches++;
        }
        Checks.Is(mismatches == 0, $"{k} input/digest-size combinations agree ({mismatches} mismatches)");
    }

    private static void Argon2idVector()
    {
        Checks.Section("Argon2id - RFC 9106 §5.3 vector");
        var tag = Argon2id.Hash(
            password: Enumerable.Repeat((byte)0x01, 32).ToArray(),
            salt: Enumerable.Repeat((byte)0x02, 16).ToArray(),
            memoryKiB: 32, passes: 3, lanes: 4, tagLength: 32,
            secret: Enumerable.Repeat((byte)0x03, 8).ToArray(),
            associatedData: Enumerable.Repeat((byte)0x04, 12).ToArray());
        Checks.Equal("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", Hex(tag),
            "Argon2id m=32 t=3 p=4 with secret and associated data");
    }

    private static void Argon2idAgainstOpenSsl()
    {
        Checks.Section("Argon2id - agreement with OpenSSL (Node crypto.argon2Sync)");
        if (Checks.Run("node", "-e", "process.exit(typeof require('crypto').argon2Sync === 'function' ? 0 : 1)") is null)
        {
            Checks.Skip("node 24.7+ is not on PATH");
            return;
        }

        var password = Encoding.UTF8.GetBytes("correct horse battery staple ✓");
        var salt = Enumerable.Range(0, 32).Select(i => (byte)(i * 7 + 3)).ToArray();

        // (memory KiB, passes, lanes, tag length): one lane, odd lane counts, memory that is
        // not a multiple of 4p, tags longer than one BLAKE2b output (the H' chain), and the
        // exact parameters a new vault uses.
        (int m, int t, int p, int len)[] cases =
        [
            (64, 1, 1, 32),
            (100, 2, 3, 32),
            (1024, 3, 4, 100),
            (4096, 1, 2, 65),
            (8192, 4, 8, 16),
            (256 * 1024, 3, 4, 32),
        ];
        foreach (var (m, t, p, len) in cases)
        {
            var stopwatch = Stopwatch.StartNew();
            var ours = Hex(Argon2id.Hash(password, salt, m, t, p, len));
            var elapsed = stopwatch.ElapsedMilliseconds;
            var theirs = Checks.Run("node", "-e",
                "const c=require('crypto');const a=process.argv.slice(1);" +
                "process.stdout.write(c.argon2Sync('argon2id',{message:Buffer.from(a[0],'hex'),nonce:Buffer.from(a[1],'hex')," +
                "memory:+a[2],passes:+a[3],parallelism:+a[4],tagLength:+a[5]}).toString('hex'))",
                Convert.ToHexStringLower(password), Convert.ToHexStringLower(salt), $"{m}", $"{t}", $"{p}", $"{len}");
            Checks.Equal(theirs ?? "(node failed)", ours, $"m={m} KiB t={t} p={p} tag={len} ({elapsed} ms here)");
        }
    }
}
