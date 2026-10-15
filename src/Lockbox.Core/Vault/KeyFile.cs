using System.Security.Cryptography;

namespace Lockbox.Core.Vault;

/// <summary>
/// An optional second factor: any file whose SHA-256 is mixed into the KEK. Kept off the
/// cloud, it makes a stolen vault file useless on its own however weak the password.
/// </summary>
public static class KeyFile
{
    public const int MaxSize = 1024 * 1024;
    public const string Extension = ".lbxkey";

    /// <summary>
    /// The path for a new key file: <see cref="Extension"/> is added when the name has none, so
    /// the file is recognisable and the file dialogs list it.
    /// </summary>
    public static string WithExtension(string path) => Path.HasExtension(path) ? path : path + Extension;

    /// <summary>Write 64 random bytes to a new owner-only file (never overwrites) and return its digest.</summary>
    public static byte[] Create(string path)
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        try
        {
            using (var stream = PrivateFiles.Create(path, FileMode.CreateNew))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>The digest that goes into the KEK. Any file up to 1 MiB works as a key file.</summary>
    public static byte[] LoadDigest(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Key file not found.", path);
        if (info.Length == 0) throw new InvalidDataException("Key file is empty.");
        if (info.Length > MaxSize) throw new InvalidDataException($"Key file is larger than {MaxSize / 1024} KiB.");
        var bytes = File.ReadAllBytes(path);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
