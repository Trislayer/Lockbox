using System.Globalization;
using System.Security.Cryptography;

namespace Lockbox.Core.Vault;

/// <summary>
/// The highest revision of each vault this device has opened or saved, kept in the user's
/// local app data rather than beside the vault. A vault file cannot tell on its own that it
/// is an older copy - every version is sealed under the same key - so this is what notices
/// when someone with access to the cloud folder puts an old version (a backup, say) back in
/// place of the current one.
/// </summary>
/// <remarks>
/// One line per vault: <c>&lt;vault id&gt; &lt;revision&gt;</c>. Best effort: if the ledger cannot
/// be read or written, opening and saving go ahead without the check rather than failing.
/// </remarks>
internal static class RevisionLedger
{
    /// <summary>Lockbox.Checks points this at a temp folder so it never touches the real ledger.</summary>
    internal static string FilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create),
        "Lockbox", "revisions.txt");

    private static readonly Lock s_gate = new();

    /// <summary>The highest revision recorded for this vault, or 0.</summary>
    public static long Seen(Guid vaultId)
    {
        lock (s_gate)
            return Read().GetValueOrDefault(vaultId);
    }

    /// <summary>Record <paramref name="revision"/> unless a higher one is already recorded.</summary>
    public static void Record(Guid vaultId, long revision)
    {
        lock (s_gate)
        {
            var ledger = Read();
            if (ledger.GetValueOrDefault(vaultId) >= revision) return;
            ledger[vaultId] = revision;
            var temp = FilePath + ".tmp-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));
            try
            {
                var directory = Path.GetDirectoryName(FilePath) ?? throw new IOException($"'{FilePath}' has no parent directory.");
                PrivateFiles.CreateDirectory(directory);
                using (var writer = new StreamWriter(PrivateFiles.Create(temp, FileMode.CreateNew)))
                    foreach (var (id, seen) in ledger)
                        writer.WriteLine($"{id:D} {seen.ToString(CultureInfo.InvariantCulture)}");
                File.Move(temp, FilePath, overwrite: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Best effort, as above.
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
        }
    }

    private static Dictionary<Guid, long> Read()
    {
        var ledger = new Dictionary<Guid, long>();
        try
        {
            if (!File.Exists(FilePath)) return ledger;
            foreach (var line in File.ReadLines(FilePath))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && Guid.TryParse(parts[0], out var id)
                    && long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var revision))
                    ledger[id] = Math.Max(revision, ledger.GetValueOrDefault(id));
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort, as above.
        }
        return ledger;
    }
}
