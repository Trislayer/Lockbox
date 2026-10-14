using System.Reflection;
using System.Security.Cryptography;

namespace Lockbox.Core;

/// <summary>
/// Random passwords and passphrases from <see cref="RandomNumberGenerator"/> only - every
/// draw is unbiased (<see cref="RandomNumberGenerator.GetInt32(int)"/> uses rejection sampling).
/// </summary>
public static class PasswordGenerator
{
    public const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    public const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Digits = "0123456789";
    // No quotes, backslash or space: generated passwords end up in connection strings and
    // shell commands, and those are the characters that break them.
    public const string Symbols = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

    private static readonly Lazy<string[]> s_words = new(LoadWords);

    /// <summary>
    /// A password of <paramref name="length"/> characters containing at least one character
    /// from every enabled class.
    /// </summary>
    public static string Generate(int length = 32, bool symbols = true)
    {
        string[] classes = symbols ? [Lowercase, Uppercase, Digits, Symbols] : [Lowercase, Uppercase, Digits];
        if (length < classes.Length) throw new ArgumentOutOfRangeException(nameof(length), $"At least {classes.Length} characters.");
        var alphabet = string.Concat(classes);

        var chars = new char[length];
        try
        {
            // One guaranteed character per class, the rest from the whole alphabet, then an
            // unbiased Fisher-Yates shuffle so the guaranteed ones are not always first.
            for (var i = 0; i < classes.Length; i++)
                chars[i] = classes[i][RandomNumberGenerator.GetInt32(classes[i].Length)];
            for (var i = classes.Length; i < length; i++)
                chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
            for (var i = length - 1; i > 0; i--)
            {
                var j = RandomNumberGenerator.GetInt32(i + 1);
                (chars[i], chars[j]) = (chars[j], chars[i]);
            }
            return new string(chars);
        }
        finally
        {
            Array.Clear(chars);
        }
    }

    /// <summary>
    /// Words from the 2048-word BIP39 list, 11 bits each: 7 words is 77 bits, the suggested
    /// minimum for a master passphrase that protects a file an attacker may hold forever.
    /// </summary>
    public static string GeneratePassphrase(int words = 7, string separator = "-")
    {
        if (words < 1) throw new ArgumentOutOfRangeException(nameof(words));
        var list = s_words.Value;
        return string.Join(separator, Enumerable.Range(0, words).Select(_ => list[RandomNumberGenerator.GetInt32(list.Length)]));
    }

    public static double PasswordEntropyBits(int length, bool symbols = true) =>
        length * Math.Log2(Lowercase.Length + Uppercase.Length + Digits.Length + (symbols ? Symbols.Length : 0));

    public static double PassphraseEntropyBits(int words) => words * Math.Log2(s_words.Value.Length);

    private static string[] LoadWords()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Lockbox.Core.bip39-english.txt")
            ?? throw new InvalidOperationException("Embedded word list is missing.");
        using var reader = new StreamReader(stream);
        var words = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length != 2048) throw new InvalidOperationException($"Word list has {words.Length} words, expected 2048.");
        return words;
    }
}
