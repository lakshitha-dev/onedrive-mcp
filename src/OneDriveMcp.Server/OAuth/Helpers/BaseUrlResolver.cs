using Microsoft.Extensions.Options;
using OneDriveMcp.Server.OAuth.Configuration;

namespace OneDriveMcp.Server.OAuth.Helpers;

/// <summary>Determines the public base URL that discovery documents advertise.</summary>
public static class BaseUrlResolver
{
    /// <summary>
    /// Resolves the base URL, preferring the configured value.
    /// </summary>
    /// <remarks>
    /// The <c>Host</c> header is attacker-controlled. Echoing it into a discovery document would
    /// let someone hand a client an authorization endpoint of their choosing, so it is only used
    /// when the host appears in <c>AllowedPublicHosts</c>, and otherwise the request is refused
    /// rather than answered with a guess.
    /// </remarks>
    public static bool TryResolve(HttpContext context, OAuthServerOptions options, out string baseUrl)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(options.PublicBaseUrl))
        {
            baseUrl = options.PublicBaseUrl.TrimEnd('/');
            return true;
        }

        var host = context.Request.Host.Value;

        if (!string.IsNullOrEmpty(host) &&
            options.AllowedPublicHosts.Any(allowed =>
                string.Equals(allowed, host, StringComparison.OrdinalIgnoreCase)))
        {
            baseUrl = $"{context.Request.Scheme}://{host}";
            return true;
        }

        baseUrl = string.Empty;
        return false;
    }

    /// <summary>Resolves the base URL, or writes a 400 and returns null.</summary>
    public static string? ResolveOrReject(HttpContext context, IOptions<OAuthServerOptions> options)
    {
        if (TryResolve(context, options.Value, out var baseUrl))
        {
            return baseUrl;
        }

        context.Response.StatusCode = StatusCodes.Status400BadRequest;

        return null;
    }
}

/// <summary>Determines the client IP behind a reverse proxy.</summary>
public static class ClientIpResolver
{
    /// <summary>
    /// Resolves the caller's IP address.
    /// </summary>
    /// <remarks>
    /// Behind Azure Front Door the connection address is the edge node, which would put every
    /// caller in the same rate-limit bucket. <c>X-Azure-ClientIP</c> is set by the edge itself and
    /// cannot be spoofed by the caller; <c>X-Forwarded-For</c> can be, so it is only a last resort.
    /// </remarks>
    public static string Resolve(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Request.Headers.TryGetValue("X-Azure-ClientIP", out var azureClientIp) &&
            azureClientIp.Count > 0 && !string.IsNullOrWhiteSpace(azureClientIp[0]))
        {
            return azureClientIp[0]!;
        }

        if (context.Connection.RemoteIpAddress is { } remote)
        {
            return remote.ToString();
        }

        return "unknown";
    }
}
