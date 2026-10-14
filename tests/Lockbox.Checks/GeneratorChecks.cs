using Lockbox.Core;

namespace Lockbox.Checks;

internal static class GeneratorChecks
{
    public static void Run()
    {
        Checks.Section("Password generator");

        var password = PasswordGenerator.Generate(40);
        Checks.Is(password.Length == 40, "comes out the requested length");
        Checks.Is(password.Any(char.IsLower) && password.Any(char.IsUpper) && password.Any(char.IsDigit)
                  && password.Any(PasswordGenerator.Symbols.Contains), "contains every class");
        Checks.Is(!password.Any(c => c is '"' or '\'' or '\\' or ' '), "never contains quotes, backslash or space");

        var plain = Enumerable.Range(0, 200).Select(_ => PasswordGenerator.Generate(12, symbols: false)).ToList();
        Checks.Is(plain.All(p => p.All(char.IsLetterOrDigit)), "symbols off means no symbols");
        Checks.Is(plain.Distinct().Count() == 200, "two hundred passwords are all different");
        Checks.Throws<ArgumentOutOfRangeException>(() => PasswordGenerator.Generate(3), "too short to hold every class is refused");

        // Every position should see every character eventually; a broken shuffle tends to
        // pin the guaranteed-class characters to the front.
        var firsts = Enumerable.Range(0, 4000).Select(_ => PasswordGenerator.Generate(8)[0]).ToHashSet();
        Checks.Is(firsts.Count > 70, $"the first character is drawn from the whole alphabet ({firsts.Count} distinct)");

        var phrase = PasswordGenerator.GeneratePassphrase(7);
        Checks.Is(phrase.Split('-').Length == 7, "a passphrase has the requested word count");
        Checks.Is(Math.Abs(PasswordGenerator.PassphraseEntropyBits(7) - 77) < 0.001, "7 BIP39 words is 77 bits");
    }
}
