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

    public string? Value(string name) => _values.GetValueOrDefault(name);
    public bool Has(string flag) => _flags.Contains(flag);

    public string? VaultPath() => Positional.FirstOrDefault() ?? NonEmpty(Environment.GetEnvironmentVariable("LOCKBOX_VAULT"));
    public string? KeyFilePath() => Value("--keyfile") ?? NonEmpty(Environment.GetEnvironmentVariable("LOCKBOX_KEYFILE"));

    private static string? NonEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;
}
