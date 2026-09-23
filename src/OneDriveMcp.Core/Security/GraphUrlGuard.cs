namespace OneDriveMcp.Core.Security;

/// <summary>
/// Allow-list for the pre-authenticated content URLs Graph hands back.
/// </summary>
/// <remarks>
/// <para>
/// Downloading a file means following a redirect to a URL that Graph chose, and then fetching it.
/// Without a check the server would issue a request to whatever host that redirect names, which
/// turns any Graph response into a server-side request forgery primitive.
/// </para>
/// <para>
/// The redirect target is also fetched with no <c>Authorization</c> header. The URL is already
/// pre-authenticated, and forwarding the Graph bearer to a third-party host would hand over the
/// caller's access to their whole drive.
/// </para>
/// </remarks>
public static class GraphUrlGuard
{
    /// <summary>Hosts, or parent domains, that content URLs are permitted to point at.</summary>
    private static readonly string[] AllowedHostSuffixes =
    [
        "graph.microsoft.com",
        ".sharepoint.com",
        ".files.1drv.com",
        ".svc.ms",
        ".onedrive.com"
    ];

    /// <summary>Returns true when the URL is HTTPS and points at an allowed Microsoft host.</summary>
    public static bool IsAllowed(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) ||
            !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        foreach (var suffix in AllowedHostSuffixes)
        {
            var isMatch = suffix.StartsWith('.')
                // A leading dot means a subdomain of that zone, so "evil-sharepoint.com" and
                // "sharepoint.com.evil.com" both fail.
                ? uri.Host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                : uri.Host.Equals(suffix, StringComparison.OrdinalIgnoreCase);

            if (isMatch)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Validates a content URL.</summary>
    /// <exception cref="InvalidOperationException">The URL is not an allowed Microsoft host.</exception>
    public static string EnsureAllowed(string? url)
    {
        if (!IsAllowed(url))
        {
            throw new InvalidOperationException(
                "Refusing to fetch a content URL that does not point at an approved Microsoft host.");
        }

        return url!;
    }
}
