using System.Globalization;
using System.Security.Cryptography;

namespace Lockbox.Core.Vault;

/// <summary>
/// An unlocked vault file: the decrypted document plus what is needed to save it again.
/// </summary>
/// <remarks>
/// <para>
/// Built for a file that lives in a synced cloud folder (Google Drive, iCloud Drive) or is
/// carried around by hand. Saving therefore:
/// </para>
/// <list type="number">
///   <item>refuses if the file changed since it was opened or last saved here (another
///   device saved through the sync client) unless forced;</item>
///   <item>copies the previous version into <c>&lt;name&gt;.backups/</c> next to the vault;</item>
///   <item>writes a temp file and renames it over the vault, so a crash or a sync client
///   reading mid-write never sees half a file;</item>
///   <item>reads the result back and checks it byte for byte.</item>
/// </list>
/// <para>
/// .NET cannot reliably wipe strings, so decrypted entries live in managed memory until the
/// GC reuses it. The data key is a byte array and is zeroed on <see cref="Dispose"/>.
/// </para>
/// </remarks>
public sealed class VaultSession : IDisposable
{
    public const string Extension = ".lbx";
    public const int DefaultBackupsToKeep = 10;

    private VaultKeys _keys;
    // After ChangeMasterKey and until the next save: the keys the file on disk and its backups
    // are still sealed under.
    private VaultKeys? _retiredKeys;
    private byte[]? _diskHash;
    private bool _disposed;

    private VaultSession(string path, VaultKeys keys, VaultDocument document, byte[]? diskHash)
    {
        Path = System.IO.Path.GetFullPath(path);
        _keys = keys;
        Document = document;
        _diskHash = diskHash;
    }

    public string Path { get; }
    public VaultDocument Document { get; }
    public bool IsDirty { get; private set; }
    public int BackupsToKeep { get; set; } = DefaultBackupsToKeep;
    public KdfParameters Kdf => _keys.Kdf;
    public bool UsesKeyFile => (_keys.Flags & VaultFlags.KeyFile) != 0;
    public string BackupDirectory => Path + ".backups";

    /// <summary>
    /// Set when this file is an older revision of the vault than this device has already
    /// opened or saved (see <see cref="RevisionLedger"/>): a backup or conflict copy opened on
    /// purpose, or an old version someone put in place of the current one.
    /// </summary>
    public string? RollbackWarning { get; private init; }

    /// <summary>Create and save a new, empty vault. Refuses to replace an existing file.</summary>
    public static VaultSession Create(string path, string password, byte[]? keyFileDigest, KdfParameters? kdf = null)
    {
        if (File.Exists(path)) throw new IOException($"'{path}' already exists.");
        var session = new VaultSession(path, VaultKeys.Create(password, keyFileDigest, kdf ?? KdfParameters.Default), new VaultDocument(), null);
        try
        {
            session.Save();
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <summary>Read the unencrypted header, e.g. to know whether to ask for a key file.</summary>
    public static VaultFormat.HeaderInfo Inspect(string path)
    {
        using var stream = File.OpenRead(path);
        var buffer = new byte[VaultFormat.HeaderLength + VaultFormat.TagSize];
        var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        return Named(path, () => VaultFormat.ReadHeader(buffer.AsSpan(0, read)));
    }

    public static VaultSession Open(string path, string password, byte[]? keyFileDigest)
    {
        var bytes = File.ReadAllBytes(path);
        var (keys, document) = Named(path, () => VaultFormat.Unseal(bytes, password, keyFileDigest));
        var seen = RevisionLedger.Seen(document.VaultId);
        RevisionLedger.Record(document.VaultId, document.Revision);
        return new VaultSession(path, keys, document, SHA256.HashData(bytes))
        {
            RollbackWarning = document.Revision >= seen ? null :
                $"{System.IO.Path.GetFullPath(path)} is an older version of this vault than this device has already seen " +
                $"(revision {document.Revision}; this device has seen {seen}). If you did not mean to open a backup or a " +
                "conflict copy, someone may have put an old copy in place of the current one: check recent changes before saving.",
        };
    }

    /// <summary>Format errors name the file they are about.</summary>
    private static T Named<T>(string path, Func<T> read)
    {
        try
        {
            return read();
        }
        catch (VaultFormatException e)
        {
            throw new VaultFormatException($"{System.IO.Path.GetFullPath(path)}: {e.Message}");
        }
    }

    public void MarkDirty()
    {
        ThrowIfDisposed();
        IsDirty = true;
    }

    /// <summary>True when the file on disk is no longer what this session last read or wrote.</summary>
    public bool HasExternalChanges()
    {
        ThrowIfDisposed();
        var onDisk = File.Exists(Path) ? File.ReadAllBytes(Path) : null;
        return !MatchesLastKnown(onDisk);
    }

    /// <summary>
    /// Other <c>.lbx</c> files beside this one whose names start with this vault's name -
    /// what Google Drive ("vault (1).lbx") and iCloud ("vault 2.lbx") call sync conflicts.
    /// </summary>
    public IReadOnlyList<string> FindPossibleConflictCopies()
    {
        var directory = System.IO.Path.GetDirectoryName(Path)
            ?? throw new InvalidOperationException($"'{Path}' has no parent directory.");
        var stem = System.IO.Path.GetFileNameWithoutExtension(Path);
        return Directory.EnumerateFiles(directory, stem + "*" + Extension)
            .Where(f => !string.Equals(System.IO.Path.GetFullPath(f), Path, StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Encrypt and write. Throws <see cref="VaultConflictException"/> if the file changed
    /// underneath this session, unless <paramref name="force"/>.
    /// </summary>
    public void Save(bool force = false)
    {
        ThrowIfDisposed();
        var onDisk = File.Exists(Path) ? File.ReadAllBytes(Path) : null;
        if (!force && !MatchesLastKnown(onDisk))
            throw new VaultConflictException(Path);

        // Past any revision this device has seen, so saving an older copy on purpose (a
        // restored backup) is not reported as a rollback from then on.
        Document.Revision = Math.Max(Document.Revision, RevisionLedger.Seen(Document.VaultId)) + 1;
        var bytes = VaultFormat.Seal(_keys, Document);
        if (onDisk is not null)
        {
            // After a password change the previous version is still under the old key; its
            // backup is written already re-sealed under the new one.
            var previous = _retiredKeys is null ? onDisk : VaultFormat.Reseal(onDisk, _retiredKeys, _keys) ?? onDisk;
            WriteBackup(previous);
        }
        WriteAtomically(Path, bytes);

        if (!File.ReadAllBytes(Path).AsSpan().SequenceEqual(bytes))
            throw new IOException($"'{Path}' did not read back as written; the previous version is in {BackupDirectory}.");

        _diskHash = SHA256.HashData(bytes);
        IsDirty = false;
        RevisionLedger.Record(Document.VaultId, Document.Revision);

        if (_retiredKeys is not null)
        {
            RekeyBackups(_retiredKeys);
            _retiredKeys.Dispose();
            _retiredKeys = null;
        }
    }

    /// <summary>
    /// Write unsaved changes so an idle lock never has to choose between staying unlocked and
    /// losing them: to the vault, or - if another device saved it in the meantime - to
    /// <c>&lt;name&gt; (unsaved &lt;time&gt;).lbx</c> beside it, sealed under the same keys, which
    /// the conflict-copy check then points out. Returns the file written.
    /// </summary>
    public string SaveBeforeLock()
    {
        try
        {
            Save();
            return Path;
        }
        catch (VaultConflictException)
        {
            var directory = System.IO.Path.GetDirectoryName(Path)
                ?? throw new InvalidOperationException($"'{Path}' has no parent directory.");
            var stem = System.IO.Path.GetFileNameWithoutExtension(Path);
            var stamp = DateTime.Now.ToString("yyyy-MM-dd HHmmss", CultureInfo.InvariantCulture);
            var copy = System.IO.Path.Combine(directory, $"{stem} (unsaved {stamp}){Extension}");
            WriteAtomically(copy, VaultFormat.Seal(_keys, Document));
            IsDirty = false;
            return copy;
        }
    }

    /// <summary>
    /// Re-key the vault under a new master password and/or key file (pass null to stop using
    /// one). A fresh data key and salt are generated, so a copy of an old file opened with an
    /// old password reveals nothing about files saved after this. Takes effect on the next
    /// Save, which also re-seals the backups under the new key, so none of them opens with the
    /// old password either.
    /// </summary>
    public void ChangeMasterKey(string password, byte[]? keyFileDigest, KdfParameters? kdf = null)
    {
        ThrowIfDisposed();
        var replacement = VaultKeys.Create(password, keyFileDigest, kdf ?? _keys.Kdf);
        if (_retiredKeys is null)
            _retiredKeys = _keys;
        else
            _keys.Dispose(); // a re-key that was never saved: nothing is sealed under it
        _keys = replacement;
        IsDirty = true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _keys.Dispose();
        _retiredKeys?.Dispose();
        foreach (var entry in Document.Entries)
            entry.History.Clear();
        Document.Entries.Clear();
    }

    private bool MatchesLastKnown(byte[]? onDisk)
    {
        if (onDisk is null) return _diskHash is null;
        if (_diskHash is null) return false;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(onDisk), _diskHash);
    }

    private void WriteBackup(byte[] previous)
    {
        PrivateFiles.CreateDirectory(BackupDirectory);
        var stem = System.IO.Path.GetFileNameWithoutExtension(Path);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);
        PrivateFiles.WriteAllBytes(System.IO.Path.Combine(BackupDirectory, $"{stem}.{stamp}{Extension}"), previous);

        var stale = new DirectoryInfo(BackupDirectory).GetFiles("*" + Extension)
            .OrderByDescending(f => f.Name, StringComparer.Ordinal)
            .Skip(Math.Max(1, BackupsToKeep));
        foreach (var file in stale)
            file.Delete();
    }

    /// <summary>
    /// After a password change: every backup still sealed under the old data key is re-sealed
    /// under the new one, and any that opens with neither (sealed before an even earlier
    /// change) is deleted, so no backup opens with a retired password.
    /// </summary>
    private void RekeyBackups(VaultKeys retired)
    {
        if (!Directory.Exists(BackupDirectory)) return;
        foreach (var file in Directory.GetFiles(BackupDirectory, "*" + Extension))
        {
            var old = File.ReadAllBytes(file);
            if (VaultFormat.Reseal(old, retired, _keys) is { } resealed)
                WriteAtomically(file, resealed);
            else if (!VaultFormat.IsSealedUnder(old, _keys))
                File.Delete(file);
        }
    }

    private static void WriteAtomically(string path, byte[] bytes)
    {
        var temp = path + ".tmp-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));
        try
        {
            using (var stream = PrivateFiles.Create(temp, FileMode.CreateNew, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
