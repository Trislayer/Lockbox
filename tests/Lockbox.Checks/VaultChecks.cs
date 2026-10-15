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
        // Never read or write the real ledger of revisions this device has seen.
        var realLedger = RevisionLedger.FilePath;
        RevisionLedger.FilePath = Path.Combine(dir, "ledger", "revisions.txt");
        try
        {
            RoundTrip(dir);
            WrongCredentials(dir);
            KeyFiles(dir);
            KeyFolderPlacement(dir);
            Tampering(dir);
            Conflicts(dir);
            Backups(dir);
            ChangeMasterKey(dir);
            BackupsFollowPasswordChange(dir);
            Rollback(dir);
            SaveBeforeLock(dir);
            OwnerOnlyFiles(dir);
            Unicode(dir);
            RealParameters(dir);
        }
        finally
        {
            RevisionLedger.FilePath = realLedger;
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

    private static void KeyFolderPlacement(string dir)
    {
        Checks.Section("Vault - the Lockbox Keys folder");
        Checks.Equal("k" + KeyFile.Extension, KeyFile.WithExtension("k"), "a new key file named without an extension gets " + KeyFile.Extension);
        Checks.Equal("k.key", KeyFile.WithExtension("k.key"), "a new key file's own extension is kept");

        var realHome = KeyFolder.Home;
        KeyFolder.Home = Path.Combine(dir, "home");
        try
        {
            var home = KeyFolder.Home;
            Checks.Is(KeyFolder.Where(Path.Combine(home, "Downloads", "k"))?.Kind == PlaceKind.Downloads, "a key file in Downloads is flagged");
            Checks.Is(KeyFolder.Where(Path.Combine(home, "Desktop", "x", "k"))?.Kind == PlaceKind.Desktop, "one on the Desktop is flagged");
            Checks.Is(KeyFolder.Where(Path.Combine(home, "Library", "Mobile Documents", "k"))?.Kind == PlaceKind.Cloud, "one in iCloud Drive is flagged as cloud");
            Checks.Is(KeyFolder.Where(Path.Combine(dir, "G", "My Drive", "k"))?.Kind == PlaceKind.Cloud, "one in a Google Drive 'My Drive' is flagged as cloud");
            Checks.Is(KeyFolder.Where(Path.Combine(home, "Downloadsfoo", "k")) is null, "a folder merely named like Downloads is not");
            Checks.Is(KeyFolder.Where(Path.Combine(KeyFolder.FolderPath, "k")) is null, "one already in Lockbox Keys is not");

            var downloads = Path.Combine(home, "Downloads");
            Directory.CreateDirectory(downloads);
            var source = Path.Combine(downloads, "vault" + KeyFile.Extension);
            var digest = KeyFile.Create(source);
            var moved = KeyFolder.MoveIn(source);
            Checks.Equal(Path.Combine(KeyFolder.FolderPath, "vault" + KeyFile.Extension), moved, "moving a key file puts it in Lockbox Keys under its own name");
            Checks.Is(!File.Exists(source), "the original is gone after the move");
            Checks.Is(digest.AsSpan().SequenceEqual(KeyFile.LoadDigest(moved)), "the moved key file has the same digest");
            Checks.Equal(moved, KeyFolder.MoveIn(moved), "moving one already there leaves it alone");

            var second = Path.Combine(downloads, "vault" + KeyFile.Extension);
            KeyFile.Create(second);
            Checks.Equal(Path.Combine(KeyFolder.FolderPath, "vault (2)" + KeyFile.Extension), KeyFolder.MoveIn(second), "a second one with the same name never overwrites the first");
            Checks.Is(digest.AsSpan().SequenceEqual(KeyFile.LoadDigest(moved)), "the first one is unchanged");
            Checks.Equal(Path.Combine(KeyFolder.FolderPath, "vault (3)" + KeyFile.Extension), KeyFolder.PlaceFor("vault"), "a new key file is placed under a free name, with the extension");

            Checks.Throws<FileNotFoundException>(() => KeyFolder.MoveIn(Path.Combine(downloads, "none")), "moving a missing key file is refused");
            var big = Path.Combine(downloads, "big.bin");
            File.WriteAllBytes(big, new byte[KeyFile.MaxSize + 1]);
            Checks.Throws<InvalidDataException>(() => KeyFolder.MoveIn(big), "a file too big to be a key file is not moved");
            Checks.Is(File.Exists(big), "and stays where it was");

            if (!OperatingSystem.IsWindows())
            {
                const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                Checks.Equal((ownerOnly | UnixFileMode.UserExecute).ToString(), File.GetUnixFileMode(KeyFolder.FolderPath).ToString(), "Lockbox Keys is 0700");
                Checks.Equal(ownerOnly.ToString(), File.GetUnixFileMode(moved).ToString(), "a moved key file is 0600");
            }
        }
        finally
        {
            KeyFolder.Home = realHome;
        }
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

        // Authentic (sealed with the right key) but with a null where the model requires text.
        using (var keys = VaultKeys.Create("pw", null, Fast))
        {
            File.WriteAllBytes(path, VaultFormat.SealJson(keys, """{"schema":1,"entries":[{"title":null,"password":"x"}]}"""u8));
            Checks.Throws<VaultFormatException>(() => VaultSession.Open(path, "pw", null), "a null in a non-nullable field is refused, not loaded as null");
            File.WriteAllBytes(path, VaultFormat.SealJson(keys, """{"schema":1,"entries":[{"title":"t"}]}"""u8));
            using (var ok = VaultSession.Open(path, "pw", null))
                Checks.Is(ok.Document.Entries.Single().Password == "", "a missing optional field takes its default");
        }

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
        var newest = backups.Order(StringComparer.Ordinal).Last();
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

    private static void BackupsFollowPasswordChange(string dir)
    {
        Checks.Section("Vault - backups follow a password change");
        var path = NewPath(dir);
        using (var vault = VaultSession.Create(path, "old", null, Fast))
        {
            for (var i = 0; i < 3; i++)
            {
                vault.Document.Entries.Add(new VaultEntry { Title = $"entry {i}" });
                vault.Save();
                Thread.Sleep(5);
            }
            // A backup from before an earlier password change: sealed under a key this session never had.
            var stale = Path.Combine(vault.BackupDirectory, "stale" + VaultSession.Extension);
            VaultSession.Create(stale, "older", null, Fast).Dispose();

            vault.ChangeMasterKey("first", null);
            vault.ChangeMasterKey("new", null); // re-keyed twice before saving: only the last counts
            vault.Save();
            Checks.Is(!File.Exists(stale), "a backup sealed under neither the old nor the new key is deleted");
        }

        var backups = Directory.GetFiles(path + ".backups");
        Checks.Is(backups.Length == 4, $"every backup under the old key is kept: the 3 earlier ones and the one this save made (found {backups.Length})");
        var openWithOld = backups.Count(b => Opens(b, "old"));
        var openWithNew = backups.Count(b => Opens(b, "new"));
        Checks.Is(openWithOld == 0, $"no backup opens with the old password ({openWithOld} did)");
        Checks.Is(openWithNew == backups.Length, $"every backup opens with the new password ({openWithNew} of {backups.Length})");
        Checks.Is(!Opens(path, "first"), "an intermediate password that was never saved opens nothing");
        var newest = backups.Order(StringComparer.Ordinal).Last();
        using (var previous = VaultSession.Open(newest, "new", null))
            Checks.Is(previous.Document.Entries.Count == 3, "the backup this save made holds the version before it");
        Checks.Is(Directory.GetFiles(path + ".backups", "*.tmp-*").Length == 0, "re-sealing leaves no temp files");
    }

    private static bool Opens(string path, string password)
    {
        try
        {
            VaultSession.Open(path, password, null).Dispose();
            return true;
        }
        catch (VaultUnlockException)
        {
            return false;
        }
    }

    private static void Rollback(string dir)
    {
        Checks.Section("Vault - an older copy put in place of the vault");
        var path = NewPath(dir);
        byte[] older;
        using (var vault = VaultSession.Create(path, "pw", null, Fast))
        {
            vault.Document.Entries.Add(new VaultEntry { Title = "one" });
            vault.Save();
            older = File.ReadAllBytes(path);
            vault.Document.Entries.Add(new VaultEntry { Title = "two" });
            vault.Save();
        }
        using (var current = VaultSession.Open(path, "pw", null))
            Checks.Is(current.RollbackWarning is null, "the current version opens without a warning");

        var current2 = File.ReadAllBytes(path);
        File.WriteAllBytes(path, older);
        using (var rolledBack = VaultSession.Open(path, "pw", null))
        {
            Checks.Is(rolledBack.RollbackWarning is not null, "an older version put back in place is reported");
            rolledBack.MarkDirty();
            rolledBack.Save();
        }
        using (var restored = VaultSession.Open(path, "pw", null))
            Checks.Is(restored.RollbackWarning is null, "once an older copy is saved on purpose, it is no longer reported");

        File.WriteAllBytes(path, current2);
        using (var superseded = VaultSession.Open(path, "pw", null))
            Checks.Is(superseded.RollbackWarning is not null, "the version that save replaced now counts as older too");
    }

    private static void SaveBeforeLock(string dir)
    {
        Checks.Section("Vault - unsaved changes at an idle lock");
        var path = NewPath(dir);
        VaultSession.Create(path, "pw", null, Fast).Dispose();
        using (var vault = VaultSession.Open(path, "pw", null))
        {
            vault.Document.Entries.Add(new VaultEntry { Title = "pending" });
            vault.MarkDirty();
            Checks.Is(vault.SaveBeforeLock() == vault.Path && !vault.IsDirty, "with no conflict they are saved to the vault");
        }

        using var laptop = VaultSession.Open(path, "pw", null);
        using (var desktop = VaultSession.Open(path, "pw", null))
        {
            desktop.Document.Entries.Add(new VaultEntry { Title = "from desktop" });
            desktop.Save();
        }
        laptop.Document.Entries.Add(new VaultEntry { Title = "from laptop" });
        laptop.MarkDirty();
        var written = laptop.SaveBeforeLock();
        Checks.Is(written != laptop.Path, "after another device saved, they go to a copy, not over the other device's version");
        using (var check = VaultSession.Open(path, "pw", null))
            Checks.Is(check.Document.Entries.All(e => e.Title != "from laptop"), "the other device's version is left as it was");
        using (var copy = VaultSession.Open(written, "pw", null))
            Checks.Is(copy.Document.Entries.Any(e => e.Title == "from laptop"), "the copy opens with the same password and holds the changes");
        Checks.Is(laptop.FindPossibleConflictCopies().Contains(written), "the copy is pointed out as a possible conflict copy");
    }

    private static void OwnerOnlyFiles(string dir)
    {
        Checks.Section("Vault - files only their owner can read");
        if (OperatingSystem.IsWindows())
        {
            Checks.Skip("Unix file modes (Windows files inherit the folder's ACL)");
            return;
        }
        const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var keyPath = Path.Combine(dir, "mode" + KeyFile.Extension);
        var digest = KeyFile.Create(keyPath);
        var path = NewPath(dir);
        using (var vault = VaultSession.Create(path, "pw", digest, Fast))
        {
            vault.MarkDirty();
            vault.Save();
        }
        var backup = Directory.GetFiles(path + ".backups").Single();
        Checks.Equal(ownerOnly.ToString(), File.GetUnixFileMode(keyPath).ToString(), "a new key file is 0600");
        Checks.Equal(ownerOnly.ToString(), File.GetUnixFileMode(path).ToString(), "the vault is 0600");
        Checks.Equal(ownerOnly.ToString(), File.GetUnixFileMode(backup).ToString(), "a backup is 0600");
        Checks.Equal((ownerOnly | UnixFileMode.UserExecute).ToString(), File.GetUnixFileMode(path + ".backups").ToString(), "the backups folder is 0700");
        Checks.Equal(ownerOnly.ToString(), File.GetUnixFileMode(RevisionLedger.FilePath).ToString(), "the revision ledger is 0600");
    }

    private static void Unicode(string dir)
    {
        Checks.Section("Vault - Unicode passwords");
        var path = NewPath(dir);
        const string composed = "café-über";      // é and ü as single code points (Windows)
        const string decomposed = "café-über";  // e + combining acute, u + combining diaeresis (macOS)
        VaultSession.Create(path, composed, null, Fast).Dispose();
        try
        {
            VaultSession.Open(path, decomposed, null).Dispose();
            Checks.Is(true, "a passphrase typed decomposed opens a vault created composed (NFC)");
        }
        catch (VaultUnlockException)
        {
            Checks.Is(false, "a passphrase typed decomposed opens a vault created composed (NFC) - it was refused");
        }
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
