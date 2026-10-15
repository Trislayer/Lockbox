using System.Reflection;
using Lockbox.Cli;
using Lockbox.Core;
using Lockbox.Core.Vault;

// lockbox <command> [args]. Vault and key file paths fall back to LOCKBOX_VAULT and
// LOCKBOX_KEYFILE so a daily `lockbox open` needs no arguments. Neither is a secret: the
// password is never taken from the command line or the environment.

try
{
    return Run(args);
}
catch (Exception e) when (e is VaultUnlockException or VaultFormatException or VaultConflictException
                              or IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
{
    Console.Error.WriteLine($"lockbox: {e.Message}");
    return 1;
}
catch (EndOfStreamException)
{
    return 1;
}

static int Run(string[] args)
{
    if (args.Length == 0 || args[0] is "help" or "-h" or "--help" or "/?")
    {
        Usage();
        return args.Length == 0 ? 1 : 0;
    }

    var options = Options.Parse(args.Skip(1));
    switch (args[0])
    {
        case "new":
            return New(options);
        case "open":
            return Open(options);
        case "keyfile":
            return CreateKeyFile(options);
        case "gen":
            Console.WriteLine(options.GeneratedSecret());
            return 0;
        case "version" or "--version":
            Console.WriteLine($"lockbox {Assembly.GetExecutingAssembly().GetName().Version?.ToString(3)}");
            Console.WriteLine("Includes the BIP39 English wordlist (MIT License); see THIRD-PARTY-NOTICES.md.");
            return 0;
        default:
            Console.Error.WriteLine($"lockbox: unknown command '{args[0]}'. Try 'lockbox help'.");
            return 1;
    }
}

static int New(Options options)
{
    var path = options.VaultPath() ?? throw new ArgumentException("Give a path for the new vault, e.g. lockbox new G:\\My Drive\\vault.lbx");
    if (!path.EndsWith(VaultSession.Extension, StringComparison.OrdinalIgnoreCase)) path += VaultSession.Extension;
    if (File.Exists(path)) throw new IOException($"'{path}' already exists.");

    byte[]? keyFile = null;
    if (options.Value("--create-keyfile") is { } newKeyOption)
    {
        var newKeyPath = KeyFile.WithExtension(newKeyOption);
        keyFile = KeyFile.Create(newKeyPath);
        Console.WriteLine($"Created key file {Path.GetFullPath(newKeyPath)}.");
        Console.WriteLine("  Keep it OFF the cloud folder, and back it up: without it the vault cannot be opened.");
    }
    else if (options.KeyFilePath() is { } keyPath)
    {
        keyFile = KeyFile.LoadDigest(keyPath);
    }

    Console.WriteLine("Choose a master password. It cannot be recovered or reset.");
    Console.WriteLine($"  Suggestion (77 bits): {PasswordGenerator.GeneratePassphrase(7)}");
    string password;
    while (true)
    {
        password = Prompt.NewSecret("Master password");
        if (password.Length >= 16 || Prompt.YesNo($"That is only {password.Length} characters. A copy of this file can be attacked offline forever. Use it anyway?"))
            break;
    }

    Console.WriteLine($"Creating {Path.GetFullPath(path)} ({KdfParameters.Default}) ...");
    using var vault = VaultSession.Create(path, password, keyFile);
    Console.WriteLine("Created. Open it with: lockbox open " + Quote(vault.Path) + (keyFile is null ? "" : " --keyfile <path>"));
    return 0;
}

static int Open(Options options)
{
    var path = options.VaultPath() ?? throw new ArgumentException("Which vault? lockbox open <file.lbx>, or set LOCKBOX_VAULT.");
    var header = VaultSession.Inspect(path);
    byte[]? keyFile = null;
    if (header.RequiresKeyFile)
    {
        var keyPath = options.KeyFilePath() ?? Prompt.Line("This vault needs its key file. Path");
        keyFile = KeyFile.LoadDigest(keyPath.Trim('"'));
    }

    for (var attempt = 1; ; attempt++)
    {
        var password = Prompt.Secret("Master password");
        try
        {
            var vault = VaultSession.Open(path, password, keyFile);
            return new Shell(vault, keyFile).Run();
        }
        catch (VaultUnlockException e) when (attempt < 3)
        {
            Console.Error.WriteLine(e.Message);
        }
    }
}

static int CreateKeyFile(Options options)
{
    var path = KeyFile.WithExtension(options.Positional.FirstOrDefault() ?? throw new ArgumentException("lockbox keyfile <path>"));
    KeyFile.Create(path);
    Console.WriteLine($"Created {Path.GetFullPath(path)}. Keep it off the cloud folder, and back it up.");
    return 0;
}

static string Quote(string path) => path.Contains(' ') ? $"\"{path}\"" : path;

static void Usage()
{
    Console.WriteLine("""
        lockbox - an encrypted password vault in a single file

        Usage:
          lockbox new <vault.lbx> [--keyfile <path> | --create-keyfile <path>]
          lockbox open [<vault.lbx>] [--keyfile <path>]     unlock and start a session
          lockbox keyfile <path>                            create a random key file
          lockbox gen [length] [--no-symbols] [--words N]   generate a password or passphrase
          lockbox version

        Put the vault in a synced folder (Google Drive, iCloud Drive) or carry it by hand; it is
        encrypted with AES-256-GCM under a key from Argon2id. Keep any key file OFF the cloud.

        Environment:
          LOCKBOX_VAULT     default vault path for 'open'
          LOCKBOX_KEYFILE   default key file path
        """);
}
