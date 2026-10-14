using System.Diagnostics;
using System.Security.Cryptography;
using Lockbox.Core;
using Lockbox.Core.Vault;

namespace Lockbox.Web;

/// <summary>Raised for "the vault is locked" so the API can answer 423.</summary>
internal sealed class VaultLockedException() : Exception("The vault is locked.");

/// <summary>
/// The one vault this process has open, if any, and every operation on it. Requests are
/// serialised through one lock: there is a single user, and unlocking (Argon2id) is the only
/// slow operation.
/// </summary>
internal sealed class VaultHost : IDisposable
{
    public static readonly TimeSpan IdleLock = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ClipboardLifetime = TimeSpan.FromSeconds(30);

    private readonly Lock _gate = new();
    private readonly Timer _idleTimer;
    private Timer? _clipboardTimer;
    private VaultSession? _vault;
    private byte[]? _keyFileDigest;
    // Stopwatch timestamps, not wall-clock times: a clock adjustment must not lock early or never.
    private long _lastActivity = Stopwatch.GetTimestamp();
    private string? _message;

    public VaultHost(string? defaultVaultPath, string? defaultKeyFilePath)
    {
        DefaultVaultPath = defaultVaultPath;
        DefaultKeyFilePath = defaultKeyFilePath;
        _idleTimer = new Timer(_ => LockIfIdle(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    public string? DefaultVaultPath { get; }
    public string? DefaultKeyFilePath { get; }

    /// <summary>Called for every API request except state polling, which must not keep the vault awake.</summary>
    public void Touch()
    {
        lock (_gate) _lastActivity = Stopwatch.GetTimestamp();
    }

    public StateResponse State()
    {
        lock (_gate)
        {
            var message = _message;
            _message = null;
            if (_vault is null)
                return new StateResponse(false, null, false, false, null, 0, false, [], null, 0,
                    DefaultVaultPath, DefaultKeyFilePath, message, (int)IdleLock.TotalMinutes);

            var backups = Directory.Exists(_vault.BackupDirectory) ? Directory.GetFiles(_vault.BackupDirectory).Length : 0;
            return new StateResponse(true, _vault.Path, _vault.IsDirty, _vault.UsesKeyFile, _vault.Kdf.ToString(),
                _vault.Document.Entries.Count, _vault.HasExternalChanges(), [.. _vault.FindPossibleConflictCopies()],
                _vault.BackupDirectory, backups, DefaultVaultPath, DefaultKeyFilePath, message, (int)IdleLock.TotalMinutes);
        }
    }

    public InspectResponse Inspect(string path)
    {
        path = Clean(path);
        if (!File.Exists(path)) return new InspectResponse(false, false, null);
        var header = VaultSession.Inspect(path);
        return new InspectResponse(true, header.RequiresKeyFile, header.Kdf.ToString());
    }

    public void Unlock(UnlockRequest request)
    {
        var path = Clean(request.Path);
        var header = VaultSession.Inspect(path);
        var digest = header.RequiresKeyFile ? KeyFile.LoadDigest(Clean(Required(request.KeyFilePath, "This vault needs its key file."))) : null;
        var vault = VaultSession.Open(path, request.Password, digest);
        Replace(vault, digest);
    }

    public string? Create(CreateRequest request)
    {
        var path = Clean(request.Path);
        if (!path.EndsWith(VaultSession.Extension, StringComparison.OrdinalIgnoreCase)) path += VaultSession.Extension;
        if (File.Exists(path)) throw new IOException($"'{path}' already exists.");
        if (request.Password.Length < 12) throw new ArgumentException("Use a master password of at least 12 characters (a 7-word passphrase is better).");

        byte[]? digest = null;
        string? createdKeyFile = null;
        if (request.CreateKeyFile)
        {
            createdKeyFile = Path.GetFullPath(Clean(Required(request.KeyFilePath, "Where should the key file go?")));
            digest = KeyFile.Create(createdKeyFile);
        }
        else if (!string.IsNullOrWhiteSpace(request.KeyFilePath))
        {
            digest = KeyFile.LoadDigest(Clean(request.KeyFilePath));
        }

        Replace(VaultSession.Create(path, request.Password, digest), digest);
        return createdKeyFile;
    }

    public void Lock(string? message = null)
    {
        lock (_gate)
        {
            _vault?.Dispose();
            _vault = null;
            if (_keyFileDigest is not null) CryptographicOperations.ZeroMemory(_keyFileDigest);
            _keyFileDigest = null;
            _message = message;
            ClearClipboardLocked();
        }
    }

    /// <summary>Clear the clipboard; a failure is queued for the page's next status poll. Caller holds _gate.</summary>
    private void ClearClipboardLocked()
    {
        if (SecureClipboard.WarningFor(SecureClipboard.ClearIfOurs()) is { } warning)
            _message = _message is null ? warning : $"{_message} {warning}";
    }

    public void Save(bool force)
    {
        lock (_gate) Open().Save(force);
    }

    public void Reload(string password)
    {
        string path;
        byte[]? digest;
        lock (_gate)
        {
            path = Open().Path;
            digest = _keyFileDigest is null ? null : (byte[])_keyFileDigest.Clone();
        }
        Replace(VaultSession.Open(path, password, digest), digest);
    }

    public string? ChangeMasterPassword(PasswdRequest request)
    {
        lock (_gate)
        {
            var vault = Open();
            // Prove the current credentials against the file before re-keying.
            using (VaultSession.Open(vault.Path, request.CurrentPassword, _keyFileDigest)) { }
            if (request.NewPassword.Length < 12) throw new ArgumentException("Use a master password of at least 12 characters.");

            string? created = null;
            var digest = request.KeyFileMode switch
            {
                "keep" => _keyFileDigest,
                "none" => null,
                "use" => KeyFile.LoadDigest(Clean(Required(request.KeyFilePath, "Which key file?"))),
                "create" => KeyFile.Create(created = Path.GetFullPath(Clean(Required(request.KeyFilePath, "Where should the key file go?")))),
                _ => throw new ArgumentException("Unknown key file option."),
            };
            vault.ChangeMasterKey(request.NewPassword, digest);
            vault.Save();
            _keyFileDigest = digest;
            return created;
        }
    }

    public EntrySummary[] List()
    {
        lock (_gate)
            return Open().Document.Sorted()
                .Select(e => new EntrySummary(e.Id, e.Title, e.Username, e.Url, e.Password.Length > 0, e.Modified))
                .ToArray();
    }

    public EntryDetail Get(Guid id)
    {
        lock (_gate) return Detail(Find(id));
    }

    public EntryDetail Add(EntryWrite write)
    {
        lock (_gate)
        {
            var vault = Open();
            var entry = new VaultEntry();
            Apply(entry, write);
            vault.Document.Entries.Add(entry);
            vault.MarkDirty();
            return Detail(entry);
        }
    }

    public EntryDetail Update(Guid id, EntryWrite write)
    {
        lock (_gate)
        {
            var vault = Open();
            var entry = Find(vault, id);
            Apply(entry, write);
            vault.MarkDirty();
            return Detail(entry);
        }
    }

    public void Delete(Guid id)
    {
        lock (_gate)
        {
            var vault = Open();
            vault.Document.Entries.Remove(Find(vault, id));
            vault.MarkDirty();
        }
    }

    public RevealResponse Reveal(Guid id)
    {
        lock (_gate) return new RevealResponse(Find(id).Password);
    }

    public HistoryItem[] History(Guid id)
    {
        lock (_gate) return Find(id).History.Select(h => new HistoryItem(h.Password, h.Retired)).ToArray();
    }

    /// <summary>
    /// Copy on the server side rather than in the page: SecureClipboard keeps the value out
    /// of Windows clipboard history and cloud sync, which the browser's clipboard API cannot.
    /// </summary>
    public string Copy(Guid id, string field)
    {
        string value;
        lock (_gate)
        {
            var entry = Find(id);
            value = field switch
            {
                "username" => entry.Username,
                "url" => entry.Url,
                "password" => entry.Password,
                _ => throw new ArgumentException($"'{field}' cannot be copied: use password, username or url."),
            };
        }
        if (value.Length == 0) throw new ArgumentException($"This entry has no {field}.");
        if (!SecureClipboard.TryCopy(value, out var error)) throw new InvalidOperationException($"Could not use the clipboard: {error}");
        lock (_gate)
        {
            // Swapped under the lock so two quick copies cannot leave an orphaned timer running.
            _clipboardTimer?.Dispose();
            _clipboardTimer = new Timer(_ => { lock (_gate) ClearClipboardLocked(); }, null, ClipboardLifetime, Timeout.InfiniteTimeSpan);
        }
        return $"Copied {field}. The clipboard is cleared in {ClipboardLifetime.TotalSeconds:0} seconds.";
    }

    public void Dispose()
    {
        _idleTimer.Dispose();
        lock (_gate) _clipboardTimer?.Dispose();
        // Nobody polls after shutdown, so a clipboard failure goes to the terminal.
        if (SecureClipboard.WarningFor(SecureClipboard.ClearIfOurs()) is { } warning)
            Console.WriteLine(warning);
        Lock();
    }

    private void LockIfIdle()
    {
        lock (_gate)
        {
            if (_vault is null || _vault.IsDirty || Stopwatch.GetElapsedTime(_lastActivity) < IdleLock) return;
        }
        Lock($"Locked after {IdleLock.TotalMinutes:0} minutes without activity.");
    }

    private void Replace(VaultSession vault, byte[]? digest)
    {
        lock (_gate)
        {
            _vault?.Dispose();
            if (_keyFileDigest is not null && !ReferenceEquals(_keyFileDigest, digest)) CryptographicOperations.ZeroMemory(_keyFileDigest);
            _vault = vault;
            _keyFileDigest = digest;
            _lastActivity = Stopwatch.GetTimestamp();
            _message = null;
        }
    }

    private VaultSession Open() => _vault ?? throw new VaultLockedException();

    private VaultEntry Find(Guid id) => Find(Open(), id);

    private static VaultEntry Find(VaultSession vault, Guid id) =>
        vault.Document.Entries.FirstOrDefault(e => e.Id == id)
        ?? throw new KeyNotFoundException($"No entry with id {id} (was it deleted, or the vault reloaded?).");

    private static void Apply(VaultEntry entry, EntryWrite write)
    {
        var title = write.Title.Trim();
        if (title.Length == 0) throw new ArgumentException("An entry needs a title.");
        entry.Title = title;
        entry.Username = write.Username;
        entry.Url = write.Url.Trim();
        entry.Notes = write.Notes.Replace("\r\n", "\n");
        if (write.Password is not null) entry.SetPassword(write.Password);
        entry.Modified = DateTimeOffset.UtcNow;
    }

    private static EntryDetail Detail(VaultEntry e) =>
        new(e.Id, e.Title, e.Username, e.Url, e.Notes, e.Password.Length > 0, e.History.Count, e.Created, e.Modified);

    private static string Required(string? value, string message) =>
        string.IsNullOrWhiteSpace(value) ? throw new ArgumentException(message) : value;

    /// <summary>Paths pasted from Explorer arrive wrapped in quotes.</summary>
    private static string Clean(string path) => path.Trim().Trim('"');
}
