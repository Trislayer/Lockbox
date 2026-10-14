using Lockbox.Core.Vault;

namespace Lockbox.Checks;

/// <summary>The file format and the save path: where a mistake loses or leaks the vault.</summary>
internal static class VaultChecks
{
    // Cheap parameters so the format checks run in milliseconds; the real ones are covered
    // by CryptoChecks and by RealParameters below.
    private static readonly KdfParameters Fast = new(64, 1, 1);

    public static void Run()
    {
        var dir = Checks.TempDirectory();
        try
        {
            RoundTrip(dir);
            WrongCredentials(dir);
            KeyFiles(dir);
            Tampering(dir);
            Conflicts(dir);
            Backups(dir);
            ChangeMasterKey(dir);
            Unicode(dir);
            RealParameters(dir);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static string NewPath(string dir) => Path.Combine(dir, Guid.NewGuid().ToString("N")[..8] + VaultSession.Extension);

    private static void RoundTrip(string dir)
    {
        Checks.Section("Vault - round trip");
        var path = NewPath(dir);
        using (var vault = VaultSession.Create(path, "hunter2", null, Fast))
        {
            vault.Document.Entries.Add(new VaultEntry
            {
                Title = "Prod SQL dbo", Username = "dbo", Password = "p@ss'w\"ord;", Url = "sql01:1433", Notes = "line 1\nline 2",
            });
            vault.MarkDirty();
            vault.Save();
        }
        using (var reopened = VaultSession.Open(path, "hunter2", null))
        {
            var e = reopened.Document.Entries.Single();
            Checks.Is(e is { Title: "Prod SQL dbo", Username: "dbo", Password: "p@ss'w\"ord;", Url: "sql01:1433", Notes: "line 1\nline 2" },
                "every field survives save and reopen");
            Checks.Is(!reopened.IsDirty, "a freshly opened vault is not dirty");
        }

        var bytes = File.ReadAllBytes(path);
        Checks.Is(!System.Text.Encoding.UTF8.GetString(bytes).Contains("dbo"), "no plaintext in the file");
        Checks.Is((bytes.Length - VaultFormat.HeaderLength - VaultFormat.TagSize) % 1024 == 0, "payload is padded to a 1 KiB multiple");
        Checks.Throws<IOException>(() => VaultSession.Create(path, "x", null, Fast), "creating over an existing file is refused");

        var header = VaultSession.Inspect(path);
        Checks.Is(header.Kdf == Fast && !header.RequiresKeyFile, "header reports KDF parameters and no key file");
    }

    private static void WrongCredentials(string dir)
    {
        Checks.Section("Vault - wrong credentials");
        var path = NewPath(dir);
        VaultSession.Create(path, "right", null, Fast).Dispose();
        Checks.Throws<VaultUnlockException>(() => VaultSession.Open(path, "wrong", null), "wrong password is rejected");
        Checks.Throws<VaultUnlockException>(() => VaultSession.Open(path, "Right", null), "password is case-sensitive");
        Checks.Throws<VaultUnlockException>(() => VaultSession.Open(path, "", null), "empty password is rejected");
    }

    private static void KeyFiles(string dir)
    {
        Checks.Section("Vault - key file");
        var keyPath = Path.Combine(dir, "a" + KeyFile.Extension);
        var digest = KeyFile.Create(keyPath);
        Checks.Is(digest.AsSpan().SequenceEqual(KeyFile.LoadDigest(keyPath)), "a created key file loads to the same digest");
        Checks.Throws<IOException>(() => KeyFile.Create(keyPath), "creating a key file never overwrites one");

        var otherDigest = KeyFile.Create(Path.Combine(dir, "b" + KeyFile.Extension));
        var path = NewPath(dir);
        VaultSession.Create(path, "pw", digest, Fast).Dispose();

        Checks.Is(VaultSession.Inspect(path).RequiresKeyFile, "header says a key file is required");
        using (var ok = VaultSession.Open(path, "pw", digest))
            Checks.Is(ok.UsesKeyFile, "password + right key file opens");
        Checks.Throws<VaultUnlockException>(() => VaultSession.Open(path, "pw", otherDigest), "right password + wrong key file is rejected");
        Checks.Throws<VaultFormatException>(() => VaultSession.Open(path, "pw", null), "missing key file is reported as missing");

        var plain = NewPath(dir);
        VaultSession.Create(plain, "pw", null, Fast).Dispose();
        Checks.Throws<VaultFormatException>(() => VaultSession.Open(plain, "pw", digest), "a key file offered to a vault that has none is reported");
    }

    private static void Tampering(string dir)
    {
        Checks.Section("Vault - tampering");
        var path = NewPath(dir);
        using (var v = VaultSession.Create(path, "pw", null, Fast))
        {
            v.Document.Entries.Add(new VaultEntry { Title = "x", Password = "y" });
            v.Save();
        }
        var original = File.ReadAllBytes(path);

        void Flip(int offset, string region, Type expected)
        {
            var copy = (byte[])original.Clone();
            copy[offset] ^= 0x01;
            File.WriteAllBytes(path, copy);
            try
            {
                VaultSession.Open(path, "pw", null).Dispose();
                Checks.Is(false, $"flipping a bit in the {region} is detected (it opened)");
            }
            catch (Exception e)
            {
                Checks.Is(e.GetType() == expected, $"flipping a bit in the {region} is detected ({e.GetType().Name})");
            }
        }

        Flip(0, "magic", typeof(VaultFormatException));
        Flip(4, "format version", typeof(VaultFormatException));
        Flip(8, "Argon2 memory (stays within bounds)", typeof(VaultUnlockException));
        Flip(25, "salt", typeof(VaultUnlockException));
        Flip(55, "wrap nonce", typeof(VaultUnlockException));
        Flip(70, "wrapped key", typeof(VaultUnlockException));
        Flip(100, "wrap tag", typeof(VaultUnlockException));
        Flip(115, "payload nonce", typeof(VaultFormatException));
        Flip(VaultFormat.HeaderLength + 3, "payload ciphertext", typeof(VaultFormatException));
        Flip(original.Length - 1, "payload tag", typeof(VaultFormatException));

        File.WriteAllBytes(path, original.AsSpan(0, original.Length - 1).ToArray());
        Checks.Throws<VaultFormatException>(() => VaultSession.Open(path, "pw", null), "a truncated file is detected");
        File.WriteAllBytes(path, [.. original, 0]);
        Checks.Throws<VaultFormatException>(() => VaultSession.Open(path, "pw", null), "an extended file is detected");

        var huge = (byte[])original.Clone();
        BitConverter.GetBytes(int.MaxValue).CopyTo(huge, 8);
        File.WriteAllBytes(path, huge);
        Checks.Throws<VaultFormatException>(() => VaultSession.Open(path, "pw", null), "an absurd memory cost is refused before allocating");
    }

    private static void Conflicts(string dir)
    {
        Checks.Section("Vault - another device saved in between");
        var path = NewPath(dir);
        VaultSession.Create(path, "pw", null, Fast).Dispose();

        using var laptop = VaultSession.Open(path, "pw", null);
        using var desktop = VaultSession.Open(path, "pw", null);
        laptop.Document.Entries.Add(new VaultEntry { Title = "from laptop" });
        laptop.Save();

        Checks.Is(desktop.HasExternalChanges(), "the other session notices the file changed");
        desktop.Document.Entries.Add(new VaultEntry { Title = "from desktop" });
        Checks.Throws<VaultConflictException>(() => desktop.Save(), "saving over someone else's change is refused");
        using (var check = VaultSession.Open(path, "pw", null))
            Checks.Is(check.Document.Entries.Single().Title == "from laptop", "the refused save left the laptop's version intact");

        desktop.Save(force: true);
        using (var check = VaultSession.Open(path, "pw", null))
            Checks.Is(check.Document.Entries.Single().Title == "from desktop", "force overwrites when asked");

        File.Delete(path);
        Checks.Throws<VaultConflictException>(() => laptop.Save(), "a vault deleted underneath the session is a conflict, not a silent recreate");

        var siblings = NewPath(dir);
        VaultSession.Create(siblings, "pw", null, Fast).Dispose();
        var stem = Path.GetFileNameWithoutExtension(siblings);
        File.WriteAllBytes(Path.Combine(dir, stem + " (1)" + VaultSession.Extension), [1]);
        using (var s = VaultSession.Open(siblings, "pw", null))
            Checks.Is(s.FindPossibleConflictCopies().Count == 1, "a Google-Drive-style conflict copy is noticed");
    }

    private static void Backups(string dir)
    {
        Checks.Section("Vault - backups");
        var path = NewPath(dir);
        using var vault = VaultSession.Create(path, "pw", null, Fast);
        vault.BackupsToKeep = 3;
        for (var i = 0; i < 6; i++)
        {
            vault.Document.Entries.Add(new VaultEntry { Title = $"entry {i}" });
            vault.Save();
            Thread.Sleep(5); // distinct millisecond timestamps in the backup names
        }
        var backups = Directory.GetFiles(vault.BackupDirectory);
        Checks.Is(backups.Length == 3, $"only the newest {vault.BackupsToKeep} backups are kept (found {backups.Length})");
        var newest = backups.Max(StringComparer.Ordinal)!;
        using (var previous = VaultSession.Open(newest, "pw", null))
            Checks.Is(previous.Document.Entries.Count == 5, "the newest backup is the version before the last save");
        Checks.Is(Directory.GetFiles(dir, "*.tmp-*").Length == 0, "no temp files are left behind");
    }

    private static void ChangeMasterKey(string dir)
    {
        Checks.Section("Vault - changing the master password");
        var path = NewPath(dir);
        using (var vault = VaultSession.Create(path, "old", null, Fast))
        {
            vault.Document.Entries.Add(new VaultEntry { Title = "kept" });
            vault.Save();
            vault.ChangeMasterKey("new", null);
            Checks.Is(vault.IsDirty, "re-keying marks the vault dirty");
            vault.Save();
        }
        Checks.Throws<VaultUnlockException>(() => VaultSession.Open(path, "old", null), "the old password no longer opens it");
        using (var v = VaultSession.Open(path, "new", null))
            Checks.Is(v.Document.Entries.Single().Title == "kept", "the new password opens it with entries intact");

        var digest = KeyFile.Create(Path.Combine(dir, "rekey" + KeyFile.Extension));
        using (var v = VaultSession.Open(path, "new", null))
        {
            v.ChangeMasterKey("new", digest);
            v.Save();
        }
        Checks.Is(VaultSession.Inspect(path).RequiresKeyFile, "a key file can be added later");
        using (var v = VaultSession.Open(path, "new", digest))
        {
            v.ChangeMasterKey("new", null);
            v.Save();
        }
        Checks.Is(!VaultSession.Inspect(path).RequiresKeyFile, "and removed again");
    }

    private static void Unicode(string dir)
    {
        Checks.Section("Vault - Unicode passwords");
        var path = NewPath(dir);
        const string composed = "café-über";      // é and ü as single code points (Windows)
        const string decomposed = "café-über";  // e + combining acute, u + combining diaeresis (macOS)
        VaultSession.Create(path, composed, null, Fast).Dispose();
        using (VaultSession.Open(path, decomposed, null))
            Checks.Is(true, "a passphrase typed decomposed opens a vault created composed (NFC)");
    }

    private static void RealParameters(string dir)
    {
        Checks.Section("Vault - default parameters");
        var path = NewPath(dir);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        VaultSession.Create(path, "pw", null).Dispose();
        var create = stopwatch.ElapsedMilliseconds;
        stopwatch.Restart();
        using (var v = VaultSession.Open(path, "pw", null))
            Checks.Is(v.Kdf == KdfParameters.Default, $"a new vault uses {KdfParameters.Default} (create {create} ms, unlock {stopwatch.ElapsedMilliseconds} ms)");
    }
}
