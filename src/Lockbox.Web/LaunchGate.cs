using System.Security.Cryptography;
using System.Text;

namespace Lockbox.Web;

/// <summary>
/// Who may talk to this server. Listening on 127.0.0.1 keeps other machines out; this keeps
/// out everything else on this machine that can make HTTP requests - other users' processes,
/// and web pages open in the browser.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><b>Launch link.</b> The terminal prints <c>/login?t=&lt;random&gt;</c>, and the
///   browser is opened on an owner-only file that redirects there - never on the link itself,
///   because other users of the machine can read process command lines. The token works
///   once; it is exchanged for an HttpOnly, SameSite=Strict session cookie, so a copy of the
///   link left in browser history is useless.</item>
///   <item><b>Host header</b> must be exactly <c>127.0.0.1:&lt;port&gt;</c> - defeats DNS
///   rebinding, where a hostile site re-points its own name at 127.0.0.1.</item>
///   <item><b>API calls</b> need the session cookie, an <c>X-Lockbox: 1</c> header and, if the
///   browser sends one, a same-origin <c>Origin</c>. A custom header makes any cross-site
///   request a CORS preflight, which this server never approves.</item>
///   <item><b>Headers</b>: strict CSP (no inline script, no third-party anything), no
///   framing, no referrer, no caching.</item>
/// </list>
/// Malware already running as the same user is out of scope: it could read the vault from
/// this process's memory or log keystrokes whatever the server did.
/// </remarks>
internal sealed class LaunchGate
{
    public const string CookieName = "lockbox_session";
    private readonly Lock _gate = new();
    private string? _launchToken = NewToken();
    private string? _sessionToken;

    /// <summary>Set once Kestrel has bound its port.</summary>
    public string ExpectedHost { get; set; } = "";

    /// <summary>Called once the launch link has been used, e.g. to delete the launch file.</summary>
    public Action? LoggedIn { get; set; }

    public string LaunchPath => $"/login?t={_launchToken}";

    /// <summary>Issue a fresh launch link (invalidating any session), e.g. after the tab was closed.</summary>
    public string Reissue()
    {
        lock (_gate)
        {
            _launchToken = NewToken();
            _sessionToken = null;
            return LaunchPath;
        }
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var response = context.Response;
        var headers = response.Headers;
        headers.ContentSecurityPolicy =
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
        headers.XFrameOptions = "DENY";
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        headers.CacheControl = "no-store";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";

        if (!string.Equals(context.Request.Host.Value, ExpectedHost, StringComparison.Ordinal))
        {
            response.StatusCode = StatusCodes.Status421MisdirectedRequest;
            return;
        }

        var path = context.Request.Path;
        if (path.Equals("/login", StringComparison.Ordinal))
        {
            await Login(context);
            return;
        }

        if (!HasSession(context))
        {
            response.StatusCode = StatusCodes.Status401Unauthorized;
            if (path.StartsWithSegments("/api")) return;
            response.ContentType = "text/plain; charset=utf-8";
            await response.WriteAsync("Lockbox: this tab is not signed in. Use the link printed in the lockbox-ui terminal (press L there for a new one).");
            return;
        }

        if (path.StartsWithSegments("/api"))
        {
            var origin = context.Request.Headers.Origin.ToString();
            if (context.Request.Headers["X-Lockbox"] != "1"
                || (origin.Length > 0 && !string.Equals(origin, "http://" + ExpectedHost, StringComparison.Ordinal)))
            {
                response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
        }

        await next(context);
    }

    private Task Login(HttpContext context)
    {
        var offered = context.Request.Query["t"].ToString();
        string session;
        lock (_gate)
        {
            if (_launchToken is null || !FixedEquals(offered, _launchToken))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/plain; charset=utf-8";
                return context.Response.WriteAsync("Lockbox: this link has already been used or is not valid. Press L in the lockbox-ui terminal for a new one.");
            }
            _launchToken = null; // single use
            session = _sessionToken = NewToken();
        }

        LoggedIn?.Invoke();
        context.Response.Cookies.Append(CookieName, session, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            IsEssential = true,
        });
        // A page that moves itself on, not a 302: when the link was opened from the launch
        // file, a redirect would still count as a cross-site navigation and the browser would
        // withhold the SameSite=Strict cookie from "/". A meta refresh starts a new, same-site one.
        context.Response.ContentType = "text/html; charset=utf-8";
        return context.Response.WriteAsync(
            "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=/\"><title>Lockbox</title>");
    }

    private bool HasSession(HttpContext context)
    {
        var cookie = context.Request.Cookies[CookieName];
        lock (_gate)
            return cookie is not null && _sessionToken is not null && FixedEquals(cookie, _sessionToken);
    }

    private static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
