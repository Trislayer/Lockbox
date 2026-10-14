using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lockbox.Web;

// What the browser and the server exchange. Passwords only travel in RevealResponse,
// HistoryResponse and the requests that set them - never in lists or entry details.

internal sealed record InspectRequest(string Path);
internal sealed record InspectResponse(bool Exists, bool RequiresKeyFile, string? Kdf);
internal sealed record UnlockRequest(string Path, string Password, string? KeyFilePath);
internal sealed record CreateRequest(string Path, string Password, string? KeyFilePath, bool CreateKeyFile);
internal sealed record ReloadRequest(string Password);
internal sealed record SaveRequest(bool Force);
/// <param name="KeyFileMode">"keep", "none", "use" (KeyFilePath is an existing file) or "create" (create it at KeyFilePath).</param>
internal sealed record PasswdRequest(string CurrentPassword, string NewPassword, string KeyFileMode, string? KeyFilePath);
internal sealed record CopyRequest(string Field);
internal sealed record GenerateRequest(int Length, bool Symbols, int Words);

internal sealed record StateResponse(
    bool Unlocked,
    string? Path,
    bool Dirty,
    bool UsesKeyFile,
    string? Kdf,
    int EntryCount,
    bool ExternalChange,
    string[] ConflictCopies,
    string? BackupDirectory,
    int BackupCount,
    string? DefaultVaultPath,
    string? DefaultKeyFilePath,
    string? Message,
    int IdleLockMinutes);

internal sealed record EntrySummary(Guid Id, string Title, string Username, string Url, bool HasPassword, DateTimeOffset Modified);

internal sealed record EntryDetail(
    Guid Id, string Title, string Username, string Url, string Notes,
    bool HasPassword, int HistoryCount, DateTimeOffset Created, DateTimeOffset Modified);

/// <param name="Password">Null keeps the current password.</param>
internal sealed record EntryWrite(string Title, string Username, string? Password, string Url, string Notes);

internal sealed record RevealResponse(string Password);
internal sealed record HistoryItem(string Password, DateTimeOffset Retired);
internal sealed record GenerateResponse(string Value, double Bits);
internal sealed record MessageResponse(string Message);
internal sealed record ErrorResponse(string Error, string Code);

// A request with a null or missing non-nullable field is rejected with 400 before a handler runs.
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, RespectNullableAnnotations = true, RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(InspectRequest))]
[JsonSerializable(typeof(InspectResponse))]
[JsonSerializable(typeof(UnlockRequest))]
[JsonSerializable(typeof(CreateRequest))]
[JsonSerializable(typeof(ReloadRequest))]
[JsonSerializable(typeof(SaveRequest))]
[JsonSerializable(typeof(PasswdRequest))]
[JsonSerializable(typeof(CopyRequest))]
[JsonSerializable(typeof(GenerateRequest))]
[JsonSerializable(typeof(StateResponse))]
[JsonSerializable(typeof(EntrySummary[]))]
[JsonSerializable(typeof(EntryDetail))]
[JsonSerializable(typeof(EntryWrite))]
[JsonSerializable(typeof(RevealResponse))]
[JsonSerializable(typeof(HistoryItem[]))]
[JsonSerializable(typeof(GenerateResponse))]
[JsonSerializable(typeof(MessageResponse))]
[JsonSerializable(typeof(ErrorResponse))]
internal sealed partial class UiJson : JsonSerializerContext;
