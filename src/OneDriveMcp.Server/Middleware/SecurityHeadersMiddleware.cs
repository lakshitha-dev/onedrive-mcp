namespace OneDriveMcp.Server.Middleware;

/// <summary>
/// Applies response security headers and removes server fingerprinting.
/// </summary>
/// <remarks>
/// This server returns JSON-RPC, not markup, so the policy can be far stricter than a normal web
/// application's: nothing is allowed to load, and nothing may frame it. The OAuth consent page
/// added in a later milestone is the one exception and relaxes this for its own route.
/// </remarks>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next ?? throw new ArgumentNullException(nameof(next));

    /// <summary>Adds the headers, then invokes the rest of the pipeline.</summary>
    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var headers = context.Response.Headers;

        headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";

        // Kestrel's own Server header is suppressed at the Kestrel level in Program.cs, because
        // it is written after this pipeline runs and removing it here does nothing. This handles
        // the ones a reverse proxy or host may add in front.
        headers.Remove("X-Powered-By");
        headers.Remove("X-AspNet-Version");

        return _next(context);
    }
}
