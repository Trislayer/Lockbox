namespace Lockbox.Core;

/// <summary>
/// Files and folders only the current user can read: 0600 / 0700 on macOS and Linux instead
/// of the umask default (usually world-readable 0644 / 0755). On Windows a new file inherits
/// its folder's ACL, which under the user profile is already private.
/// </summary>
public static class PrivateFiles
{
    private const UnixFileMode OwnerReadWrite = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public static FileStream Create(string path, FileMode mode, FileOptions options = FileOptions.None)
    {
        var streamOptions = new FileStreamOptions
        {
            Mode = mode,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = options,
        };
        if (!OperatingSystem.IsWindows())
            streamOptions.UnixCreateMode = OwnerReadWrite;
        return new FileStream(path, streamOptions);
    }

    /// <summary>Write <paramref name="bytes"/> to a new or replaced file; a replaced file keeps its mode.</summary>
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = Create(path, FileMode.Create);
        stream.Write(bytes);
    }

    public static void CreateDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(path);
        else
            Directory.CreateDirectory(path, OwnerReadWrite | UnixFileMode.UserExecute);
    }
}
