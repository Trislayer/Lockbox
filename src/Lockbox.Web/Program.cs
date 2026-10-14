using System.Diagnostics;
using System.Net;
using System.Reflection;
using Lockbox.Core;
using Lockbox.Core.Vault;
using Lockbox.Web;

// lockbox-ui [vault.lbx] [--keyfile <path>] [--port N] [--no-browser]
// Serves the vault UI on http://127.0.0.1:<port> to this machine's browser only, opens it,
// and runs until Quit in the page, Q or Ctrl+C in the terminal.

string? vaultArg = null, keyFileArg = null;
var port = 0;
var openBrowser = true;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--keyfile" when i + 1 < args.Length: keyFileArg = args[++i]; break;
        case "--port" when i + 1 < args.Length: port = int.Parse(args[++i]); break;
        case "--no-browser": openBrowser = false; break;
        case "-h" or "--help":
            Console.WriteLine("lockbox-ui [vault.lbx] [--keyfile <path>] [--port N] [--no-browser]");
            return 0;
        default: vaultArg = args[i]; break;
    }
}
vaultArg ??= Environment.GetEnvironmentVariable("LOCKBOX_VAULT") is { Length: > 0 } v ? v : null;
keyFileArg ??= Environment.GetEnvironmentVariable("LOCKBOX_KEYFILE") is { Length: > 0 } k ? k : null;

var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [] });
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Listen(IPAddress.Loopback, port);
    kestrel.AddServerHeader = false;
    kestrel.Limits.MaxRequestBodySize = 1024 * 1024;
});
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.TypeInfoResolverChain.Insert(0, UiJson.Default);
    // Request binding uses these options, not UiJson's own, so the null rules are set here too.
    o.SerializerOptions.RespectNullableAnnotations = true;
    o.SerializerOptions.RespectRequiredConstructorParameters = true;
});

var host = new VaultHost(vaultArg is null ? null : Path.GetFullPath(vaultArg), keyFileArg is null ? null : Path.GetFullPath(keyFileArg));
var gate = new LaunchGate();
var app = builder.Build();
app.Use(gate.InvokeAsync);

// ---- the page --------------------------------------------------------------------------

var assets = LoadAssets();
foreach (var (route, (bytes, contentType)) in assets)
    app.MapGet(route, () => Results.Bytes(bytes, contentType));

// ---- the API ---------------------------------------------------------------------------

var api = app.MapGroup("/api");
api.AddEndpointFilter(async (context, next) =>
{
    var request = context.HttpContext.Request;
    if (!(HttpMethods.IsGet(request.Method) && request.Path.Equals("/api/state")))
        host.Touch();
    try
    {
        return await next(context);
    }
    catch (Exception e)
    {
        var (status, code) = e switch
        {
            VaultLockedException => (StatusCodes.Status423Locked, "locked"),
            VaultUnlockException => (StatusCodes.Status400BadRequest, "unlock"),
            VaultConflictException => (StatusCodes.Status409Conflict, "conflict"),
            KeyNotFoundException => (StatusCodes.Status404NotFound, "missing"),
            VaultFormatException or ArgumentException or IOException or UnauthorizedAccessException
                or InvalidDataException or InvalidOperationException => (StatusCodes.Status400BadRequest, "invalid"),
            _ => (StatusCodes.Status500InternalServerError, "error"),
        };
        var message = status == 500 ? "Unexpected error: " + e.GetType().Name : e.Message;
        return Results.Json(new ErrorResponse(message, code), UiJson.Default.ErrorResponse, statusCode: status);
    }
});

IResult State() => Results.Json(host.State(), UiJson.Default.StateResponse);
IResult Message(string text) => Results.Json(new MessageResponse(text), UiJson.Default.MessageResponse);

api.MapGet("/state", State);
api.MapPost("/inspect", (InspectRequest r) => Results.Json(host.Inspect(r.Path), UiJson.Default.InspectResponse));
api.MapPost("/unlock", (UnlockRequest r) => { host.Unlock(r); return State(); });
api.MapPost("/create", (CreateRequest r) =>
{
    var keyFile = host.Create(r);
    return Message(keyFile is null
        ? "Vault created."
        : $"Vault created. Key file written to {keyFile} - keep it off the cloud folder and back it up; without it the vault cannot be opened.");
});
api.MapPost("/lock", () => { host.Lock("Locked."); return State(); });
api.MapPost("/save", (SaveRequest r) => { host.Save(r.Force); return State(); });
api.MapPost("/reload", (ReloadRequest r) => { host.Reload(r.Password); return State(); });
api.MapPost("/passwd", (PasswdRequest r) =>
{
    var keyFile = host.ChangeMasterPassword(r);
    return Message("Master password changed and saved. Older backups still open with the old password."
        + (keyFile is null ? "" : $" New key file: {keyFile} - keep it off the cloud folder and back it up."));
});
api.MapGet("/entries", () => Results.Json(host.List(), UiJson.Default.EntrySummaryArray));
api.MapPost("/entries", (EntryWrite w) => Results.Json(host.Add(w), UiJson.Default.EntryDetail));
api.MapGet("/entries/{id:guid}", (Guid id) => Results.Json(host.Get(id), UiJson.Default.EntryDetail));
api.MapPut("/entries/{id:guid}", (Guid id, EntryWrite w) => Results.Json(host.Update(id, w), UiJson.Default.EntryDetail));
api.MapDelete("/entries/{id:guid}", (Guid id) => { host.Delete(id); return Message("Deleted."); });
api.MapPost("/entries/{id:guid}/reveal", (Guid id) => Results.Json(host.Reveal(id), UiJson.Default.RevealResponse));
api.MapPost("/entries/{id:guid}/history", (Guid id) => Results.Json(host.History(id), UiJson.Default.HistoryItemArray));
api.MapPost("/entries/{id:guid}/copy", (Guid id, CopyRequest r) => Message(host.Copy(id, r.Field)));
api.MapPost("/generate", (GenerateRequest r) => Results.Json(r.Words > 0
    ? new GenerateResponse(PasswordGenerator.GeneratePassphrase(Math.Clamp(r.Words, 3, 24)), PasswordGenerator.PassphraseEntropyBits(Math.Clamp(r.Words, 3, 24)))
    : new GenerateResponse(PasswordGenerator.Generate(Math.Clamp(r.Length, 8, 128), r.Symbols), PasswordGenerator.PasswordEntropyBits(Math.Clamp(r.Length, 8, 128), r.Symbols)),
    UiJson.Default.GenerateResponse));
api.MapPost("/quit", (IHostApplicationLifetime lifetime) =>
{
    host.Lock();
    _ = Task.Delay(300).ContinueWith(_ => lifetime.StopApplication());
    return Message("Lockbox has stopped. You can close this tab.");
});

// ---- run -------------------------------------------------------------------------------

await app.StartAsync();
var origin = app.Urls.First(); // http://127.0.0.1:<port>
gate.ExpectedHost = new Uri(origin).Authority;

void Announce(string launchPath)
{
    var url = origin + launchPath;
    Console.WriteLine($"Lockbox UI: {url}");
    Console.WriteLine("  (single-use link; L = new link, Q = lock and quit)");
    if (openBrowser) OpenBrowser(url);
}

Console.WriteLine($"lockbox-ui {Assembly.GetExecutingAssembly().GetName().Version?.ToString(3)} - listening on {origin} (this machine only)");
Announce(gate.LaunchPath);

if (!Console.IsInputRedirected)
{
    var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
    _ = Task.Run(() =>
    {
        while (!lifetime.ApplicationStopping.IsCancellationRequested)
        {
            var key = Console.ReadKey(intercept: true).Key;
            if (key == ConsoleKey.L) Announce(gate.Reissue());
            else if (key == ConsoleKey.Q) lifetime.StopApplication();
        }
    });
}

try
{
    await app.WaitForShutdownAsync();
}
finally
{
    host.Dispose();
    Console.WriteLine("Locked and stopped.");
}
return 0;

static Dictionary<string, (byte[] Bytes, string ContentType)> LoadAssets()
{
    var assembly = Assembly.GetExecutingAssembly();
    byte[] Read(string name)
    {
        using var stream = assembly.GetManifestResourceStream("ui/" + name) ?? throw new InvalidOperationException($"Missing embedded ui/{name}.");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
    return new()
    {
        ["/"] = (Read("index.html"), "text/html; charset=utf-8"),
        ["/app.js"] = (Read("app.js"), "text/javascript; charset=utf-8"),
        ["/app.css"] = (Read("app.css"), "text/css; charset=utf-8"),
        ["/icon.svg"] = (Read("icon.svg"), "image/svg+xml"),
    };
}

static void OpenBrowser(string url)
{
    try
    {
        if (OperatingSystem.IsWindows())
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        else if (OperatingSystem.IsMacOS())
            Process.Start("open", [url]);
        else
            Process.Start("xdg-open", [url]);
    }
    catch (Exception e)
    {
        Console.WriteLine($"  Could not open a browser ({e.Message}); open the link above yourself.");
    }
}
