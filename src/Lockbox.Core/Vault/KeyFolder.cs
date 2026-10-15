namespace Lockbox.Core.Vault;

/// <summary>
/// "Lockbox Keys" in the user's home folder: an owner-only place for key files. A key file
/// left in Downloads gets swept away with the rest; one on the Desktop, in Documents or in a
/// cloud folder is usually synced - next to the vault it was meant to be kept apart from.
/// The home folder itself is not synced by iCloud, OneDrive or Google Drive.
/// </summary>
public static class KeyFolder
{
    public const string Name = "Lockbox Keys";

    /// <summary>The user's home folder; the checks point it at a scratch folder.</summary>
    public static string Home { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static string FolderPath => Path.Combine(Home, Name);

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

    /// <summary>Which risky place <paramref name="path"/> is in, or null if none is recognised.</summary>
    public static Place? Where(string path)
    {
        var full = Path.GetFullPath(path);
        if (IsUnder(full, FolderPath)) return null;
        // Cloud folders first: on macOS, Desktop and Documents can themselves be iCloud folders.
        (string Folder, string Name)[] cloud =
        [
            (Path.Combine(Home, "Library", "Mobile Documents"), "iCloud Drive"),
            (Path.Combine(Home, "Library", "CloudStorage"), "a cloud storage folder"),
            (Path.Combine(Home, "iCloudDrive"), "iCloud Drive"),
            (Path.Combine(Home, "Dropbox"), "Dropbox"),
            (Path.Combine(Home, "Google Drive"), "Google Drive"),
            (Environment.GetEnvironmentVariable("OneDrive") ?? "", "OneDrive"),
            (Environment.GetEnvironmentVariable("OneDriveConsumer") ?? "", "OneDrive"),
            (Environment.GetEnvironmentVariable("OneDriveCommercial") ?? "", "OneDrive"),
        ];
        foreach (var (folder, name) in cloud)
            if (folder.Length > 0 && IsUnder(full, folder)) return new Place(PlaceKind.Cloud, name);
        var parts = full.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Contains("My Drive", StringComparer.OrdinalIgnoreCase)) return new Place(PlaceKind.Cloud, "Google Drive");
        if (IsUnder(full, Home))
        {
            var top = Path.GetRelativePath(Home, full).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)[0];
            if (top.StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase)) return new Place(PlaceKind.Cloud, "OneDrive");
        }

        (string Folder, PlaceKind Kind, string Name)[] local =
        [
            (Path.Combine(Home, "Downloads"), PlaceKind.Downloads, "Downloads"),
            (Path.Combine(Home, "Desktop"), PlaceKind.Desktop, "Desktop"),
            (Path.Combine(Home, "Documents"), PlaceKind.Documents, "Documents"),
        ];
        foreach (var (folder, kind, name) in local)
            if (IsUnder(full, folder)) return new Place(kind, name);
        return null;
    }

    /// <summary>
    /// Move a key file into the folder: copy it (never over an existing file), read the copy
    /// back and compare, and only then delete the original. Returns the new path.
    /// </summary>
    public static string MoveIn(string path)
    {
        var source = Path.GetFullPath(path);
        var info = new FileInfo(source);
        if (!info.Exists) throw new FileNotFoundException("Key file not found.", source);
        if (info.Length == 0 || info.Length > KeyFile.MaxSize)
            throw new InvalidDataException($"'{source}' is not a key file (empty, or larger than {KeyFile.MaxSize / 1024} KiB).");
        if (IsUnder(source, FolderPath)) return source;

        PrivateFiles.CreateDirectory(FolderPath);
        var bytes = File.ReadAllBytes(source);
        var target = FreeName(Path.GetFileName(source));
        using (var stream = PrivateFiles.Create(target, FileMode.CreateNew))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        if (!File.ReadAllBytes(target).AsSpan().SequenceEqual(bytes))
        {
            File.Delete(target);
            throw new IOException($"The copy in {FolderPath} did not match the original, so it was removed and '{source}' left where it was.");
        }
        File.Delete(source);
        return target;
    }

    /// <summary>A path in the folder (created if need be) for a new key file called <paramref name="fileName"/>.</summary>
    public static string PlaceFor(string fileName)
    {
        PrivateFiles.CreateDirectory(FolderPath);
        return FreeName(Path.GetFileName(KeyFile.WithExtension(fileName)));
    }

    /// <summary><paramref name="fileName"/> in the folder, or "name (2).ext" and so on if it is taken.</summary>
    private static string FreeName(string fileName)
    {
        var candidate = Path.Combine(FolderPath, fileName);
        var stem = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        for (var n = 2; File.Exists(candidate); n++)
            candidate = Path.Combine(FolderPath, $"{stem} ({n}){extension}");
        return candidate;
    }

    private static bool IsUnder(string full, string folder)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)) + Path.DirectorySeparatorChar;
        return full.StartsWith(root, PathComparison);
    }
}

public enum PlaceKind { Downloads, Desktop, Documents, Cloud }

/// <param name="Name">For messages: "Downloads", "iCloud Drive", "a cloud storage folder", ...</param>
public sealed record Place(PlaceKind Kind, string Name);
