using System.Security.Cryptography;
using Lockbox.Core;
using Lockbox.Core.Vault;

namespace Lockbox.Cli;

/// <summary>The interactive session after unlocking: one password prompt, many commands.</summary>
internal sealed class Shell(VaultSession vault, byte[]? keyFileDigest)
{
    private static readonly TimeSpan ClipboardLifetime = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan IdleLock = TimeSpan.FromMinutes(10);

    private VaultSession _vault = vault;
    private byte[]? _keyFileDigest = keyFileDigest;
    private Timer? _clipboardTimer;
    private Timer? _idleTimer;

    public int Run()
    {
        Console.CancelKeyPress += OnCancel;
        _idleTimer = new Timer(_ => OnIdle(), null, IdleLock, Timeout.InfiniteTimeSpan);
        try
        {
            Console.WriteLine($"Unlocked {_vault.Path} - {_vault.Document.Entries.Count} entries. Type 'help' for commands.");
            WarnAboutRollback();
            WarnAboutConflictCopies();

            while (true)
            {
                Console.Write(_vault.IsDirty ? "lockbox*> " : "lockbox> ");
                var line = Console.ReadLine();
                _idleTimer.Change(IdleLock, Timeout.InfiniteTimeSpan);
                if (line is null) return Quit(force: true);

                var parts = Options.Split(line);
                if (parts.Count == 0) continue;
                var command = parts[0].ToLowerInvariant();
                var rest = parts.Skip(1).ToList();
                try
                {
                    if (command is "quit" or "exit" or "q" or "lock")
                    {
                        if (ConfirmLeave()) return Quit(force: false);
                        continue;
                    }
                    Dispatch(command, rest);
                }
                catch (VaultConflictException e)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine("  'reload' discards your unsaved changes and loads the newer file;");
                    Console.WriteLine("  'save --force' overwrites it (the overwritten version is kept in the backups folder).");
                }
                catch (Exception e) when (e is ArgumentException or FormatException or IOException or VaultUnlockException or VaultFormatException or InvalidOperationException)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }
        finally
        {
            Console.CancelKeyPress -= OnCancel;
            _idleTimer?.Dispose();
            _clipboardTimer?.Dispose();
            ClearClipboard();
            _vault.Dispose();
            if (_keyFileDigest is not null) CryptographicOperations.ZeroMemory(_keyFileDigest);
        }
    }

    private static void ClearClipboard()
    {
        if (SecureClipboard.WarningFor(SecureClipboard.ClearIfOurs()) is { } warning)
            Console.WriteLine($"\n{warning}");
    }

    private void Dispatch(string command, List<string> args)
    {
        var options = Options.Parse(args);
        var target = string.Join(' ', options.Positional);
        switch (command)
        {
            case "help" or "?": Help(); break;
            case "list" or "ls": List(target); break;
            case "show": Show(One(target), reveal: false); break;
            case "reveal": Show(One(target), reveal: true); break;
            case "copy" or "cp": Copy(options); break;
            case "add" or "new": Add(target); break;
            case "edit": Edit(One(target)); break;
            case "rm" or "delete": Remove(One(target)); break;
            case "history": History(One(target)); break;
            case "gen": Console.WriteLine(options.GeneratedSecret()); break;
            case "save": Save(options.Has("--force")); break;
            case "reload": Reload(); break;
            case "passwd": ChangeMasterPassword(options); break;
            case "info": Info(); break;
            case "clear" or "cls": Console.Clear(); break;
            default: Console.WriteLine($"Unknown command '{command}'. Type 'help'."); break;
        }
    }

    private static void Help() => Console.WriteLine("""
          list [filter]            entries, numbered (filter matches title, username, URL)
          show <entry>             details, password hidden
          reveal <entry>           details including the password (it stays in your scrollback)
          copy <entry> [field]     copy password (or: username, url) for 30 seconds
          add [title]              new entry
          edit <entry>             change an entry; Enter keeps a field
          rm <entry>               delete an entry
          history <entry>          previous passwords of an entry
          gen [len] [--no-symbols] [--words N]
          save [--force]           write the vault (refuses if another device changed it, unless --force)
          reload                   discard unsaved changes and re-read the file
          passwd [--keyfile <p> | --create-keyfile <p> | --no-keyfile]
                                   change the master password (and key file)
          info                     file, encryption parameters, backups, sync conflicts
          quit                     lock and exit (asks about unsaved changes)

          <entry> is a list number, a title, or any unique part of a title/username/URL.
        """);

    private VaultEntry One(string query)
    {
        if (query.Length == 0) throw new ArgumentException("Which entry? Give a list number, a title or part of one.");
        var matches = _vault.Document.Find(query);
        if (matches.Count == 1) return matches[0];
        if (matches.Count == 0) throw new ArgumentException($"No entry matches '{query}'.");
        var sorted = _vault.Document.Sorted();
        Console.WriteLine($"'{query}' matches {matches.Count} entries:");
        foreach (var m in matches)
            Console.WriteLine($"  {sorted.IndexOf(m) + 1,3}  {m.Title}  {m.Username}");
        throw new ArgumentException("Use the number to pick one.");
    }

    private void List(string filter)
    {
        var sorted = _vault.Document.Sorted();
        if (sorted.Count == 0)
        {
            Console.WriteLine("The vault is empty. 'add' creates an entry.");
            return;
        }
        var titleWidth = Math.Min(40, sorted.Max(e => e.Title.Length));
        var shown = 0;
        for (var i = 0; i < sorted.Count; i++)
        {
            var e = sorted[i];
            if (!VaultDocument.Matches(e, filter)) continue;
            Console.WriteLine($"  {i + 1,3}  {Truncate(e.Title, 40).PadRight(titleWidth)}  {e.Username}");
            shown++;
        }
        if (shown == 0) Console.WriteLine($"Nothing matches '{filter}'.");
    }

    private static void Show(VaultEntry e, bool reveal)
    {
        Console.WriteLine($"  Title     {e.Title}");
        Console.WriteLine($"  Username  {e.Username}");
        Console.WriteLine($"  Password  {(reveal ? e.Password : e.Password.Length == 0 ? "" : "******** (reveal / copy)")}");
        if (e.Url.Length > 0) Console.WriteLine($"  URL       {e.Url}");
        if (e.Notes.Length > 0)
        {
            Console.WriteLine("  Notes");
            foreach (var line in e.Notes.Split('\n')) Console.WriteLine($"    {line}");
        }
        Console.WriteLine($"  Modified  {e.Modified.ToLocalTime():yyyy-MM-dd HH:mm}{(e.History.Count > 0 ? $"   ({e.History.Count} previous passwords: history)" : "")}");
    }

    private void Copy(Options options)
    {
        // "copy <entry> [field]": the last word is the field only if it names one.
        var words = options.Positional;
        var field = "password";
        if (words.Count > 1 && words[^1].ToLowerInvariant() is "password" or "pass" or "pw" or "username" or "user" or "url")
        {
            field = words[^1].ToLowerInvariant();
            words = words[..^1];
        }
        var e = One(string.Join(' ', words));
        var value = field switch
        {
            "username" or "user" => e.Username,
            "url" => e.Url,
            _ => e.Password,
        };
        if (value.Length == 0)
        {
            Console.WriteLine($"'{e.Title}' has no {field}.");
            return;
        }
        if (!SecureClipboard.TryCopy(value, out var error))
        {
            Console.WriteLine($"Could not use the clipboard: {error}");
            return;
        }
        _clipboardTimer?.Dispose();
        _clipboardTimer = new Timer(_ => ClearClipboard(), null, ClipboardLifetime, Timeout.InfiniteTimeSpan);
        Console.WriteLine($"Copied the {field} of '{e.Title}'. It is cleared in {ClipboardLifetime.TotalSeconds:0} seconds.");
    }

    private void Add(string title)
    {
        var entry = new VaultEntry
        {
            Title = title.Length > 0 ? title : Required("Title"),
            Username = Prompt.Line("Username"),
        };
        entry.Password = AskPassword(existing: false) ?? "";
        entry.Url = Prompt.Line("URL");
        entry.Notes = Prompt.MultiLine("Notes", allowKeep: false) ?? "";
        _vault.Document.Entries.Add(entry);
        _vault.MarkDirty();
        Console.WriteLine($"Added '{entry.Title}'. Not saved yet - 'save' writes the vault.");
    }

    private void Edit(VaultEntry e)
    {
        e.Title = Prompt.Line("Title", e.Title);
        e.Username = Prompt.Line("Username", e.Username);
        if (AskPassword(existing: true) is { } password) e.SetPassword(password);
        e.Url = Prompt.Line("URL", e.Url);
        if (Prompt.MultiLine("Notes", allowKeep: true) is { } notes) e.Notes = notes;
        e.Modified = DateTimeOffset.UtcNow;
        _vault.MarkDirty();
        Console.WriteLine($"Updated '{e.Title}'. Not saved yet.");
    }

    /// <summary>Null means keep the current password.</summary>
    private static string? AskPassword(bool existing)
    {
        var choice = Prompt.Line(existing
            ? "Password: [k]eep, [g]enerate or [t]ype"
            : "Password: [g]enerate or [t]ype", existing ? "k" : "g").Trim().ToLowerInvariant();
        switch (choice)
        {
            case "k" or "keep" when existing:
                return null;
            case "t" or "type":
                return Prompt.NewSecret("Password");
            default:
                int length;
                while (true)
                {
                    try
                    {
                        length = Options.WholeNumber(Prompt.Line("Length", "32"), "password length", 8, 1024);
                        break;
                    }
                    catch (ArgumentException e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
                var symbols = Prompt.YesNo("Include symbols?", defaultYes: true);
                var generated = PasswordGenerator.Generate(length, symbols);
                Console.WriteLine($"Generated a {length}-character password ({PasswordGenerator.PasswordEntropyBits(length, symbols):0} bits). Use 'copy' or 'reveal' to get it.");
                return generated;
        }
    }

    private void Remove(VaultEntry e)
    {
        if (!Prompt.YesNo($"Delete '{e.Title}' ({e.Username})?")) return;
        _vault.Document.Entries.Remove(e);
        _vault.MarkDirty();
        Console.WriteLine("Deleted. Not saved yet.");
    }

    private static void History(VaultEntry e)
    {
        if (e.History.Count == 0)
        {
            Console.WriteLine($"'{e.Title}' has no previous passwords.");
            return;
        }
        if (!Prompt.YesNo($"Show {e.History.Count} previous passwords of '{e.Title}' on screen?")) return;
        foreach (var h in e.History)
            Console.WriteLine($"  {h.Retired.ToLocalTime():yyyy-MM-dd HH:mm}  {h.Password}");
    }

    private void Save(bool force)
    {
        _vault.Save(force);
        Console.WriteLine($"Saved {_vault.Path}.");
    }

    private void Reload()
    {
        if (_vault.IsDirty && !Prompt.YesNo("Discard your unsaved changes and reload the file?")) return;
        var password = Prompt.Secret("Master password");
        var reopened = VaultSession.Open(_vault.Path, password, _keyFileDigest);
        _vault.Dispose();
        _vault = reopened;
        Console.WriteLine($"Reloaded - {_vault.Document.Entries.Count} entries.");
        WarnAboutRollback();
        WarnAboutConflictCopies();
    }

    private void ChangeMasterPassword(Options options)
    {
        var current = Prompt.Secret("Current master password");
        // Verify against the file as it is on disk; this also proves the key file.
        using (VaultSession.Open(_vault.Path, current, _keyFileDigest)) { }

        var keyFile = _keyFileDigest;
        if (options.Has("--no-keyfile")) keyFile = null;
        else if (options.Value("--create-keyfile") is { } create)
        {
            keyFile = KeyFile.Create(create);
            Console.WriteLine($"Created key file {Path.GetFullPath(create)} - keep it off the cloud, and back it up.");
        }
        else if (options.Value("--keyfile") is { } existing) keyFile = KeyFile.LoadDigest(existing);

        var password = Prompt.NewSecret("New master password");
        if (password.Length < 16 && !Prompt.YesNo($"That is only {password.Length} characters. Use it anyway?")) return;

        _vault.ChangeMasterKey(password, keyFile);
        _keyFileDigest = keyFile;
        _vault.Save();
        Console.WriteLine("Master password changed and saved, and the backups re-encrypted to match. Copies made before this -");
        Console.WriteLine("  your cloud provider's own version history and trash, or anything already downloaded - still open with the old password.");
    }

    private void Info()
    {
        Console.WriteLine($"  File        {_vault.Path}");
        Console.WriteLine($"  Encryption  AES-256-GCM, key from {_vault.Kdf}{(_vault.UsesKeyFile ? " + key file" : "")}");
        Console.WriteLine($"  Entries     {_vault.Document.Entries.Count}{(_vault.IsDirty ? " (unsaved changes)" : "")}");
        var backups = Directory.Exists(_vault.BackupDirectory) ? Directory.GetFiles(_vault.BackupDirectory).Length : 0;
        Console.WriteLine($"  Backups     {backups} in {_vault.BackupDirectory}");
        Console.WriteLine($"  On disk     {(_vault.HasExternalChanges() ? "CHANGED since opened (another device saved?) - see 'reload'" : "unchanged since opened/saved")}");
        WarnAboutConflictCopies();
    }

    private void WarnAboutRollback()
    {
        if (_vault.RollbackWarning is { } warning) Console.WriteLine($"WARNING: {warning}");
    }

    private void WarnAboutConflictCopies()
    {
        var copies = _vault.FindPossibleConflictCopies();
        if (copies.Count == 0) return;
        Console.WriteLine("Note: these files next to the vault look like sync-conflict copies. Open each to check");
        Console.WriteLine("for entries made on another device before deleting it:");
        foreach (var c in copies) Console.WriteLine($"  {c}");
    }

    private bool ConfirmLeave()
    {
        if (!_vault.IsDirty) return true;
        var answer = Prompt.Line("Unsaved changes. [s]ave and quit, [d]iscard and quit, or [c]ancel", "c").Trim().ToLowerInvariant();
        switch (answer)
        {
            case "s" or "save":
                Save(force: false);
                return true;
            case "d" or "discard":
                return true;
            default:
                return false;
        }
    }

    private static int Quit(bool force)
    {
        Console.WriteLine(force ? "\nLocked." : "Locked.");
        return 0;
    }

    private void OnIdle()
    {
        var saved = "";
        if (_vault.IsDirty)
        {
            try
            {
                var written = _vault.SaveBeforeLock();
                saved = written == _vault.Path
                    ? " Your unsaved changes were saved first."
                    : $" Another device had saved the vault, so your unsaved changes were written to {written} - open it to copy them across.";
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Locking now would throw the changes away; try again after another idle period.
                Console.WriteLine($"\n[idle {IdleLock.TotalMinutes:0} min - could not save your unsaved changes ({e.Message}), so not locking; save or quit]");
                _idleTimer?.Change(IdleLock, Timeout.InfiniteTimeSpan);
                return;
            }
        }
        ClearClipboard();
        _vault.Dispose();
        Console.WriteLine($"\nLocked after {IdleLock.TotalMinutes:0} minutes idle.{saved}");
        Environment.Exit(0);
    }

    private void OnCancel(object? sender, ConsoleCancelEventArgs e)
    {
        ClearClipboard();
        if (_vault.IsDirty) Console.WriteLine("\nUnsaved changes were discarded.");
        _vault.Dispose();
    }

    private static string Required(string label)
    {
        while (true)
        {
            var value = Prompt.Line(label).Trim();
            if (value.Length > 0) return value;
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}
