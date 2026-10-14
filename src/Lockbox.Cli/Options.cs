namespace Lockbox.Cli;

/// <summary>Minimal argument parsing: positionals, <c>--flag</c> and <c>--name value</c>.</summary>
internal sealed class Options
{
    // Options that take a value; everything else starting with -- is a boolean flag.
    private static readonly HashSet<string> Valued = ["--keyfile", "--create-keyfile", "--words"];

    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    public List<string> Positional { get; } = [];

    public static Options Parse(IEnumerable<string> args)
    {
        var options = new Options();
        using var e = args.GetEnumerator();
        while (e.MoveNext())
        {
            var arg = e.Current;
            if (Valued.Contains(arg))
            {
                if (!e.MoveNext()) throw new ArgumentException($"{arg} needs a value.");
                options._values[arg] = e.Current;
            }
            else if (arg.StartsWith("--", StringComparison.Ordinal))
                options._flags.Add(arg);
            else
                options.Positional.Add(arg);
        }
        return options;
    }

    /// <summary>Same parsing for a line typed inside the session, honouring double quotes.</summary>
    public static List<string> Split(string line)
    {
        var parts = new List<string>();
        var current = new System.Text.StringBuilder();
        var quoted = false;
        var any = false;
        foreach (var c in line)
        {
            if (c == '"')
            {
                quoted = !quoted;
                any = true;
            }
            else if (char.IsWhiteSpace(c) && !quoted)
            {
                if (any) parts.Add(current.ToString());
                current.Clear();
                any = false;
            }
            else
            {
                current.Append(c);
                any = true;
            }
        }
        if (any) parts.Add(current.ToString());
        return parts;
    }

    /// <summary>
    /// <c>gen [length] [--no-symbols] [--words N]</c>, shared by the command line and the session.
    /// </summary>
    public string GeneratedSecret()
    {
        if (Value("--words") is { } words)
            return Core.PasswordGenerator.GeneratePassphrase(WholeNumber(words, "--words", 1, 64));
        var length = Positional.FirstOrDefault() is { } l ? WholeNumber(l, "password length", 8, 1024) : 32;
        return Core.PasswordGenerator.Generate(length, symbols: !Has("--no-symbols"));
    }

    /// <summary>Parse a number the user typed; the error names the value and the accepted range.</summary>
    public static int WholeNumber(string text, string what, int min, int max) =>
        int.TryParse(text.Trim(), out var n) && n >= min && n <= max
            ? n
            : throw new ArgumentException($"'{text}' is not a valid {what}: give a whole number from {min} to {max}.");

    public string? Value(string name) => _values.GetValueOrDefault(name);
    public bool Has(string flag) => _flags.Contains(flag);

    public string? VaultPath() => Positional.FirstOrDefault() ?? NonEmpty(Environment.GetEnvironmentVariable("LOCKBOX_VAULT"));
    public string? KeyFilePath() => Value("--keyfile") ?? NonEmpty(Environment.GetEnvironmentVariable("LOCKBOX_KEYFILE"));

    private static string? NonEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;
}
