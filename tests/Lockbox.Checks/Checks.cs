using System.Diagnostics;

namespace Lockbox.Checks;

internal static class Checks
{
    public static int Passed { get; private set; }
    public static int Failed { get; private set; }
    public static int Skipped { get; private set; }

    public static void Section(string name) => Console.WriteLine($"\n== {name}");

    /// <summary>
    /// Run a group of checks. An exception that escapes it is a FAIL, and the groups after it
    /// still run, so one broken group cannot hide the state of the rest.
    /// </summary>
    public static void Group(string name, Action run)
    {
        try
        {
            run();
        }
        catch (Exception e)
        {
            Is(false, $"{name} threw {e.GetType().Name}: {e.Message} - the checks after it in {name} did not run");
        }
    }

    public static void Is(bool condition, string description)
    {
        if (condition)
        {
            Passed++;
            Console.WriteLine($"  ok    {description}");
        }
        else
        {
            Failed++;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  FAIL  {description}");
            Console.ResetColor();
        }
    }

    public static void Equal(string expected, string actual, string description) =>
        Is(expected == actual, expected == actual ? description : $"{description} (expected {expected}, got {actual})");

    public static void Throws<TException>(Action action, string description) where TException : Exception
    {
        try
        {
            action();
            Is(false, description + " (nothing was thrown)");
        }
        catch (TException)
        {
            Is(true, description);
        }
        catch (Exception e)
        {
            Is(false, $"{description} (threw {e.GetType().Name}: {e.Message})");
        }
    }

    public static void Skip(string description)
    {
        Skipped++;
        Console.WriteLine($"  skip  {description}");
    }

    /// <summary>Run an external tool; null if it is not installed or fails.</summary>
    public static string? Run(string fileName, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var arg in args) psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi);
            if (process is null) return null;
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0 ? output.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    public static string TempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "lockbox-checks-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(path);
        return path;
    }
}
