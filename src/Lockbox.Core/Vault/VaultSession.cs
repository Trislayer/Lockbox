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
        stream.ReadExactly(buffer);
        return VaultFormat.ReadHeader(buffer);
    }

    public static VaultSession Open(string path, string password, byte[]? keyFileDigest)
    {
        var bytes = File.ReadAllBytes(path);
        var (keys, document) = VaultFormat.Unseal(bytes, password, keyFileDigest);
        return new VaultSession(path, keys, document, SHA256.HashData(bytes));
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
        var directory = System.IO.Path.GetDirectoryName(Path)!;
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

        var bytes = VaultFormat.Seal(_keys, Document);
        if (onDisk is not null)
            WriteBackup(onDisk);
        WriteAtomically(Path, bytes);

        if (!File.ReadAllBytes(Path).AsSpan().SequenceEqual(bytes))
            throw new IOException($"'{Path}' did not read back as written; the previous version is in {BackupDirectory}.");

        _diskHash = SHA256.HashData(bytes);
        IsDirty = false;
    }

    /// <summary>
    /// Re-key the vault under a new master password and/or key file (pass null to stop using
    /// one). A fresh data key and salt are generated, so a copy of an old file opened with an
    /// old password reveals nothing about files saved after this. Takes effect on the next Save.
    /// </summary>
    public void ChangeMasterKey(string password, byte[]? keyFileDigest, KdfParameters? kdf = null)
    {
        ThrowIfDisposed();
        var replacement = VaultKeys.Create(password, keyFileDigest, kdf ?? _keys.Kdf);
        _keys.Dispose();
        _keys = replacement;
        IsDirty = true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _keys.Dispose();
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
        Directory.CreateDirectory(BackupDirectory);
        var stem = System.IO.Path.GetFileNameWithoutExtension(Path);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);
        File.WriteAllBytes(System.IO.Path.Combine(BackupDirectory, $"{stem}.{stamp}{Extension}"), previous);

        var stale = new DirectoryInfo(BackupDirectory).GetFiles("*" + Extension)
            .OrderByDescending(f => f.Name, StringComparer.Ordinal)
            .Skip(Math.Max(1, BackupsToKeep));
        foreach (var file in stale)
            file.Delete();
    }

    private static void WriteAtomically(string path, byte[] bytes)
    {
        var temp = path + ".tmp-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
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
