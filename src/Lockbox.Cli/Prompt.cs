using System.Text;

namespace Lockbox.Cli;

/// <summary>Console input. Secrets are read without echo and never printed back.</summary>
internal static class Prompt
{
    public static string Line(string label, string? current = null)
    {
        Console.Write(current is null ? $"{label}: " : $"{label} [{current}]: ");
        var line = Console.ReadLine() ?? throw new EndOfStreamException();
        return line.Length == 0 && current is not null ? current : line;
    }

    public static bool YesNo(string question, bool defaultYes = false)
    {
        Console.Write($"{question} {(defaultYes ? "[Y/n]" : "[y/N]")} ");
        var answer = (Console.ReadLine() ?? "").Trim();
        return answer.Length == 0 ? defaultYes : answer.StartsWith('y') || answer.StartsWith('Y');
    }

    /// <summary>Read a secret without echoing it (not even as asterisks: length is information too).</summary>
    public static string Secret(string label)
    {
        Console.Write($"{label}: ");
        if (Console.IsInputRedirected)
        {
            // Windows PowerShell 5.1 starts piped UTF-8 with a byte-order mark, which would
            // otherwise become the first character of the password.
            var line = Console.ReadLine() ?? throw new EndOfStreamException();
            return line.TrimStart('﻿');
        }

        var buffer = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0) buffer.Length--;
                continue;
            }
            if (key.Key == ConsoleKey.Escape)
            {
                buffer.Clear();
                continue;
            }
            if (!char.IsControl(key.KeyChar)) buffer.Append(key.KeyChar);
        }
        Console.WriteLine();
        var secret = buffer.ToString();
        buffer.Clear();
        return secret;
    }

    /// <summary>Ask twice; loop until the two match.</summary>
    public static string NewSecret(string label)
    {
        while (true)
        {
            var first = Secret(label);
            var second = Secret("Again to confirm");
            if (first == second) return first;
            Console.WriteLine("They did not match - try again.");
        }
    }

    /// <summary>Lines until a line containing only ".". Empty first line means "keep".</summary>
    public static string? MultiLine(string label, bool allowKeep)
    {
        Console.WriteLine(allowKeep
            ? $"{label} (end with a line containing only '.'; Enter alone keeps the current text):"
            : $"{label} (end with a line containing only '.'; Enter alone for none):");
        var lines = new List<string>();
        while (true)
        {
            var line = Console.ReadLine();
            if (line is null || line == ".") break;
            if (lines.Count == 0 && line.Length == 0) return allowKeep ? null : "";
            lines.Add(line);
        }
        return string.Join("\n", lines);
    }
}
