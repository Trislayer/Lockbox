using System.Text.Json.Serialization;

namespace Lockbox.Core.Vault;

/// <summary>The decrypted contents of a vault. Only ever exists in memory.</summary>
public sealed class VaultDocument
{
    public int Schema { get; set; } = 1;
    public List<VaultEntry> Entries { get; set; } = [];

    /// <summary>Entries in display order; list numbers refer to this order.</summary>
    public List<VaultEntry> Sorted() =>
        Entries.OrderBy(e => e.Title, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Created).ToList();

    /// <summary>
    /// Resolve what a user typed to entries: a list number, an exact title (any case), or
    /// else every entry whose title, username or URL contains the text.
    /// </summary>
    public List<VaultEntry> Find(string query)
    {
        var sorted = Sorted();
        query = query.Trim();
        if (int.TryParse(query, out var number) && number >= 1 && number <= sorted.Count)
            return [sorted[number - 1]];
        var exact = sorted.Where(e => string.Equals(e.Title, query, StringComparison.OrdinalIgnoreCase)).ToList();
        if (exact.Count > 0) return exact;
        return sorted.Where(e => Matches(e, query)).ToList();
    }

    public static bool Matches(VaultEntry entry, string filter) =>
        filter.Length == 0
        || entry.Title.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || entry.Username.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || entry.Url.Contains(filter, StringComparison.OrdinalIgnoreCase);
}

public sealed class VaultEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Url { get; set; } = "";
    public string Notes { get; set; } = "";
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset Modified { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Every password this entry has had, newest first. A rotated credential that turns out
    /// to still be live somewhere is only recoverable if the old value was kept.
    /// </summary>
    public List<PasswordHistoryItem> History { get; set; } = [];

    /// <summary>Change the password, keeping the old one in <see cref="History"/>.</summary>
    public void SetPassword(string password)
    {
        if (password == Password) return;
        if (Password.Length > 0)
            History.Insert(0, new PasswordHistoryItem { Password = Password, Retired = DateTimeOffset.UtcNow });
        Password = password;
        Modified = DateTimeOffset.UtcNow;
    }
}

public sealed class PasswordHistoryItem
{
    public string Password { get; set; } = "";
    public DateTimeOffset Retired { get; set; }
}

/// <summary>Source-generated JSON (no reflection), so Native AOT and trimming are safe.</summary>
[JsonSourceGenerationOptions(WriteIndented = false, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(VaultDocument))]
internal sealed partial class VaultJson : JsonSerializerContext;
