using System.Text;

namespace Lockbox.Checks;

/// <summary>
/// Conventions enforced by scanning the repository's own source. Every corpus read goes
/// through <see cref="Corpus"/>, which throws on a missing root and on a root with no files,
/// so a moved folder fails the run instead of passing it.
/// </summary>
internal static class ConventionChecks
{
    public static void Run()
    {
        var root = RepoRoot();
        ScannerSeesWhatItShould();
        NullableIsAnError(root);
        NoNullForgivingOperator(root);
        JsonRespectsNullableAnnotations(root);
        NoPackageReferences(root);
        InHouseCryptoIsConfined(root);
        EveryCheckClassIsProvenAndRun(root);
        EveryEmbeddedResourceIsCredited(root);
    }

    /// <summary>
    /// Every file under a project's Resources/ folder is third-party or data content that ships
    /// inside the executables, so THIRD-PARTY-NOTICES.md names it and the build copies that
    /// notice beside each executable.
    /// </summary>
    private static void EveryEmbeddedResourceIsCredited(string root)
    {
        Checks.Section("Conventions - shipped third-party content is credited");
        var notices = File.ReadAllText(Path.Combine(root, "THIRD-PARTY-NOTICES.md"));
        var uncredited = new List<string>();
        foreach (var file in Corpus(root, "*", Path.Combine("src", "Lockbox.Core", "Resources")))
            if (!notices.Contains(Path.GetFileName(file), StringComparison.Ordinal))
                uncredited.Add(Relative(root, file));
        Report(uncredited, "THIRD-PARTY-NOTICES.md names every embedded resource",
            "add a section to THIRD-PARTY-NOTICES.md with the file's source, author and license text");

        var targets = File.ReadAllText(Path.Combine(root, "Directory.Build.targets"));
        Checks.Is(targets.Contains("THIRD-PARTY-NOTICES.md", StringComparison.Ordinal) && targets.Contains("CopyToPublishDirectory", StringComparison.Ordinal),
            "Directory.Build.targets copies THIRD-PARTY-NOTICES.md into every executable's publish output");
    }

    /// <summary>
    /// The one exception to "crypto from the base class library": Argon2id and BLAKE2b, which
    /// .NET does not ship. They stay in Crypto/, only VaultFormat calls them, and adding a
    /// file to Crypto/ is a deliberate edit to this list.
    /// </summary>
    /// <remarks>Blind spot: a call through reflection, or a type alias (`using X = ...Argon2id`).</remarks>
    private static void InHouseCryptoIsConfined(string root)
    {
        Checks.Section("Conventions - in-house crypto stays in one place");
        var cryptoFolder = Path.Combine("src", "Lockbox.Core", "Crypto");
        var files = Corpus(root, "*.cs", cryptoFolder).Select(f => Path.GetFileName(f)).Order(StringComparer.Ordinal).ToList();
        Checks.Is(files.SequenceEqual(["Argon2id.cs", "Blake2b.cs"]),
            $"Crypto/ holds exactly Argon2id.cs and Blake2b.cs (found {string.Join(", ", files)}) - a new primitive needs its own vectors in CryptoChecks and an entry here");

        var allowed = new[] { Path.Combine(cryptoFolder, "Argon2id.cs"), Path.Combine(cryptoFolder, "Blake2b.cs"), Path.Combine("src", "Lockbox.Core", "Vault", "VaultFormat.cs") };
        var hits = new List<string>();
        foreach (var file in Corpus(root, "*.cs", "src"))
        {
            var relative = Relative(root, file);
            if (allowed.Contains(relative, StringComparer.OrdinalIgnoreCase)) continue;
            var code = CodeOnly(File.ReadAllText(file));
            foreach (var name in new[] { "Argon2id", "Blake2b" })
                if (ContainsIdentifier(code, name))
                    hits.Add($"{relative} uses {name}");
        }
        Report(hits, "only VaultFormat.cs calls the in-house primitives",
            "go through VaultFormat / VaultSession instead of calling Argon2id or Blake2b directly");
    }

    /// <summary>Every check class has a recorded failure proof in Proofs.cs and is run by Program.cs.</summary>
    private static void EveryCheckClassIsProvenAndRun(string root)
    {
        Checks.Section("Conventions - every check class has been seen to fail");
        var classes = new List<string>();
        foreach (var file in Corpus(root, "*.cs", "tests"))
        {
            var code = CodeOnly(File.ReadAllText(file));
            var at = 0;
            while ((at = code.IndexOf("static class ", at, StringComparison.Ordinal)) >= 0)
            {
                at += "static class ".Length;
                var end = at;
                while (end < code.Length && (char.IsLetterOrDigit(code[end]) || code[end] == '_')) end++;
                var name = code[at..end];
                if (name.EndsWith("Checks", StringComparison.Ordinal) && name != "Checks") classes.Add(name);
            }
        }
        Checks.Is(classes.Count >= 4, $"found the check classes ({classes.Count}, expected at least 4)");

        var program = CodeOnly(File.ReadAllText(Path.Combine(root, "tests", "Lockbox.Checks", "Program.cs")));
        var unproven = classes.Where(c => !Proofs.Recorded.ContainsKey(c)).ToList();
        var ghosts = Proofs.Recorded.Keys.Where(k => !classes.Contains(k)).ToList();
        var unrun = classes.Where(c => !ContainsIdentifier(program, $"nameof({c})")).ToList();
        Report(unproven, "every check class has a recorded proof",
            "break the code the class defends, watch it go red, restore, and add the result to Proofs.Recorded");
        Report(ghosts, "every recorded proof names a class that exists", "remove the entry from Proofs.Recorded");
        Report(unrun, "every check class is run by Program.cs", "add Checks.Group(nameof(...), ....Run) to Program.cs");
    }

    private static bool ContainsIdentifier(string code, string name)
    {
        for (var at = code.IndexOf(name, StringComparison.Ordinal); at >= 0; at = code.IndexOf(name, at + 1, StringComparison.Ordinal))
        {
            var before = at == 0 ? ' ' : code[at - 1];
            var after = at + name.Length < code.Length ? code[at + name.Length] : ' ';
            if (!(char.IsLetterOrDigit(before) || before == '_') && !(char.IsLetterOrDigit(after) || after == '_'))
                return true;
        }
        return false;
    }

    /// <summary>The `!` scanner itself: it must flag every planted use and nothing that only looks like one.</summary>
    private static void ScannerSeesWhatItShould()
    {
        Checks.Section("Conventions - the null-forgiving scanner");
        const string planted = """
            var a = x!.Length;
            var b = Call()!;
            var c = items[0]!;
            if (a != b && !flag) { }
            var s = "Hello!";
            var v = @"Wow!" + $"Yes! {n}";
            var r = \"\"\"Raw!\"\"\";
            var ch = '!';
            // comment x!.y
            /* block x! */
            """;
        var sites = NullForgivingSites(planted.Replace("\\\"", "\"")).Select(s => s.Line).ToList();
        Checks.Is(sites.SequenceEqual([1, 2, 3]), $"flags lines 1-3 and nothing in operators, strings, chars or comments (got [{string.Join(", ", sites)}])");
    }

    /// <summary>
    /// The build settings that make nullable warnings compile errors stay in one place
    /// (Directory.Build.props), and nothing switches them off or suppresses them locally.
    /// </summary>
    /// <remarks>Blind spot: suppression through an .editorconfig severity or a [SuppressMessage] attribute.</remarks>
    private static void NullableIsAnError(string root)
    {
        Checks.Section("Conventions - nullable warnings are compile errors");

        var props = File.ReadAllText(Path.Combine(root, "Directory.Build.props"));
        Checks.Is(props.Contains("<Nullable>enable</Nullable>", StringComparison.Ordinal),
            "Directory.Build.props enables nullable reference types (restore <Nullable>enable</Nullable>)");
        Checks.Is(props.Contains("<TreatWarningsAsErrors>true</TreatWarningsAsErrors>", StringComparison.Ordinal),
            "Directory.Build.props treats warnings as errors (restore <TreatWarningsAsErrors>true</TreatWarningsAsErrors>)");
        Checks.Is(props.Contains("<WarningsAsErrors>$(WarningsAsErrors);nullable</WarningsAsErrors>", StringComparison.Ordinal),
            "Directory.Build.props makes the nullable warning group an error on its own (restore <WarningsAsErrors>$(WarningsAsErrors);nullable</WarningsAsErrors>)");

        var overrides = new List<string>();
        foreach (var project in Corpus(root, "*.csproj", "src", "tests"))
        {
            var text = File.ReadAllText(project);
            foreach (var setting in new[] { "<Nullable>", "<TreatWarningsAsErrors>", "<WarningsAsErrors>", "<NoWarn>", "<WarningLevel>" })
                if (text.Contains(setting, StringComparison.OrdinalIgnoreCase))
                    overrides.Add($"{Relative(root, project)} sets {setting}");
        }
        Report(overrides, "no project overrides the shared warning settings",
            "delete the setting from the .csproj; warning settings live only in Directory.Build.props");

        var suppressions = new List<string>();
        foreach (var file in Corpus(root, "*.cs", "src", "tests"))
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line.StartsWith("#nullable", StringComparison.Ordinal)
                    || (line.StartsWith("#pragma warning disable", StringComparison.Ordinal) && (line.Contains("CS86", StringComparison.Ordinal) || line.Contains("nullable", StringComparison.OrdinalIgnoreCase))))
                    suppressions.Add($"{Relative(root, file)}:{i + 1}  {line}");
            }
        }
        Report(suppressions, "no #nullable directive or nullable #pragma in source",
            "remove the directive and fix the warning it was hiding");
    }

    /// <summary>
    /// No null-forgiving operator (<c>x!</c>, <c>Call()!</c>). It silences the compiler while the
    /// value can still be null at run time; throw with a message (<c>?? throw ...</c>) or
    /// restructure so the compiler can see the value is set.
    /// </summary>
    /// <remarks>
    /// Blind spots: a <c>!</c> inside an interpolation hole of an interpolated string (holes are
    /// treated as string content), and a <c>!</c> separated from its operand by whitespace.
    /// </remarks>
    private static void NoNullForgivingOperator(string root)
    {
        Checks.Section("Conventions - no null-forgiving operator");
        var hits = new List<string>();
        foreach (var file in Corpus(root, "*.cs", "src", "tests"))
            foreach (var (line, text) in NullForgivingSites(File.ReadAllText(file)))
                hits.Add($"{Relative(root, file)}:{line}  {text}");
        Report(hits, "no `!` null-forgiving operator in src or tests",
            "replace `x!` with `x ?? throw new ...(\"<what was null, and where>\")`, or restructure so the compiler sees it is set");
    }

    /// <summary>
    /// The JSON serializer ignores nullable annotations unless told otherwise, so a null in a
    /// vault file or an API request would reach a non-nullable property. Both places that set
    /// serializer options need it: each JsonSerializerContext, and the web host's HttpJsonOptions.
    /// </summary>
    private static void JsonRespectsNullableAnnotations(string root)
    {
        Checks.Section("Conventions - JSON respects nullable annotations");
        var contexts = 0;
        var hosts = 0;
        var missing = new List<string>();
        foreach (var file in Corpus(root, "*.cs", "src"))
        {
            var text = File.ReadAllText(file);
            // ASP.NET binds request bodies with its own HttpJsonOptions, not the context's options.
            if (text.Contains("ConfigureHttpJsonOptions", StringComparison.Ordinal))
            {
                hosts++;
                if (!text.Contains("SerializerOptions.RespectNullableAnnotations = true", StringComparison.Ordinal)
                    || !text.Contains("SerializerOptions.RespectRequiredConstructorParameters = true", StringComparison.Ordinal))
                    missing.Add($"{Relative(root, file)}: ConfigureHttpJsonOptions does not set SerializerOptions.RespectNullableAnnotations/RespectRequiredConstructorParameters = true");
            }
            if (!text.Contains(": JsonSerializerContext", StringComparison.Ordinal)) continue;
            contexts++;
            if (!text.Contains("RespectNullableAnnotations = true", StringComparison.Ordinal))
                missing.Add($"{Relative(root, file)}: no RespectNullableAnnotations = true");
            if (!text.Contains("RespectRequiredConstructorParameters = true", StringComparison.Ordinal))
                missing.Add($"{Relative(root, file)}: no RespectRequiredConstructorParameters = true");
        }
        // A floor as well as a guard: the scan must actually find the two contexts (vault file, web API).
        Checks.Is(contexts >= 2, $"found the JSON contexts to check ({contexts}, expected at least 2)");
        Checks.Is(hosts >= 1, $"found the web host's JSON options to check ({hosts}, expected at least 1)");
        Report(missing, "every JsonSerializerContext rejects nulls in non-nullable members",
            "add RespectNullableAnnotations = true and RespectRequiredConstructorParameters = true to its [JsonSourceGenerationOptions]");
    }

    /// <summary>Lockbox takes no NuGet dependencies; everything is the base class library or in-house.</summary>
    private static void NoPackageReferences(string root)
    {
        Checks.Section("Conventions - no NuGet dependencies");
        var hits = new List<string>();
        foreach (var project in Corpus(root, "*.csproj", "src", "tests"))
        {
            var text = File.ReadAllText(project);
            if (text.Contains("<PackageReference", StringComparison.OrdinalIgnoreCase) || text.Contains("<PackageVersion", StringComparison.OrdinalIgnoreCase))
                hits.Add(Relative(root, project));
        }
        foreach (var central in new[] { "Directory.Packages.props", "packages.config" })
            if (File.Exists(Path.Combine(root, central)))
                hits.Add(central);
        Report(hits, "no project references a NuGet package",
            "remove the package; use the base class library or write it in Lockbox.Core with checks against a published reference");
    }

    /// <summary>
    /// Every <c>!</c> that follows an identifier, <c>)</c> or <c>]</c> and is not part of
    /// <c>!=</c>, after blanking comments and string/char literals.
    /// </summary>
    internal static IEnumerable<(int Line, string Text)> NullForgivingSites(string source)
    {
        var code = CodeOnly(source);
        var lines = source.Split('\n');
        var line = 1;
        for (var i = 0; i < code.Length; i++)
        {
            if (code[i] == '\n') line++;
            if (code[i] != '!' || i == 0) continue;
            var previous = code[i - 1];
            var next = i + 1 < code.Length ? code[i + 1] : ' ';
            if (next == '=') continue;
            if (char.IsLetterOrDigit(previous) || previous is '_' or ')' or ']')
                yield return (line, lines[line - 1].Trim());
        }
    }

    /// <summary>
    /// The source with comments and the contents of string and char literals replaced by
    /// spaces (newlines kept, so line numbers still match).
    /// </summary>
    internal static string CodeOnly(string s)
    {
        var output = new StringBuilder(s.Length);
        var i = 0;
        void Blank(int end)
        {
            for (; i < end && i < s.Length; i++) output.Append(s[i] == '\n' ? '\n' : ' ');
        }
        while (i < s.Length)
        {
            var c = s[i];
            var next = i + 1 < s.Length ? s[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                var end = s.IndexOf('\n', i);
                Blank(end < 0 ? s.Length : end);
            }
            else if (c == '/' && next == '*')
            {
                var end = s.IndexOf("*/", i + 2, StringComparison.Ordinal);
                Blank(end < 0 ? s.Length : end + 2);
            }
            else if (c == '"' || ((c is '$' or '@') && (next == '"' || (next is '$' or '@' && i + 2 < s.Length && s[i + 2] == '"'))))
            {
                // Prefix ($, @, $@, @$), then the literal itself.
                var start = i;
                var verbatim = false;
                while (s[i] != '"')
                {
                    verbatim |= s[i] == '@';
                    i++;
                }
                var quotes = 0;
                while (i + quotes < s.Length && s[i + quotes] == '"') quotes++;
                int end;
                if (quotes >= 3)
                {
                    var closing = new string('"', quotes);
                    var close = s.IndexOf(closing, i + quotes, StringComparison.Ordinal);
                    end = close < 0 ? s.Length : close + quotes;
                }
                else if (quotes == 2)
                {
                    end = i + 2; // "" - an empty string
                }
                else
                {
                    end = i + 1;
                    while (end < s.Length)
                    {
                        if (!verbatim && s[end] == '\\') { end += 2; continue; }
                        if (s[end] == '"')
                        {
                            if (verbatim && end + 1 < s.Length && s[end + 1] == '"') { end += 2; continue; }
                            end++;
                            break;
                        }
                        if (!verbatim && s[end] == '\n') break;
                        end++;
                    }
                }
                i = start;
                Blank(end);
            }
            else if (c == '\'')
            {
                var end = i + 1;
                while (end < s.Length && s[end] != '\'' && s[end] != '\n')
                    end += s[end] == '\\' ? 2 : 1;
                Blank(Math.Min(s.Length, end + 1));
            }
            else
            {
                output.Append(c);
                i++;
            }
        }
        return output.ToString();
    }

    private static void Report(List<string> violations, string description, string fix)
    {
        Checks.Is(violations.Count == 0, violations.Count == 0
            ? description
            : $"{description}; {violations.Count} found - fix: {fix}\n        " + string.Join("\n        ", violations));
    }

    /// <summary>Files under each root; throws if a root is missing or holds no matching file.</summary>
    private static List<string> Corpus(string root, string pattern, params string[] folders)
    {
        var files = new List<string>();
        foreach (var folder in folders)
        {
            var path = Path.Combine(root, folder);
            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException($"Convention scan root '{path}' does not exist; update ConventionChecks if it moved.");
            var found = Directory.EnumerateFiles(path, pattern, SearchOption.AllDirectories)
                .Where(f => !IsBuildOutput(root, f))
                .ToList();
            if (found.Count == 0)
                throw new InvalidOperationException($"Convention scan root '{path}' has no {pattern} files; update ConventionChecks if it moved.");
            files.AddRange(found);
        }
        return files;
    }

    private static bool IsBuildOutput(string root, string file)
    {
        var parts = Relative(root, file).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return parts.Any(p => p is "bin" or "obj");
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Lockbox.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException($"No Lockbox.slnx above '{AppContext.BaseDirectory}'; run the checks from the repository.");
    }

    private static string Relative(string root, string path) => Path.GetRelativePath(root, path);
}
