namespace OneDriveMcp.Server.Auth;

/// <summary>
/// Authentication options, bound from the <c>Auth</c> configuration section.
/// </summary>
public sealed class AuthOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Auth";

    /// <summary>
    /// Whether to require an authenticated caller on the MCP endpoint.
    /// </summary>
    /// <remarks>
    /// Disabling it leaves the endpoint anonymous, which is only tenable behind a pasted
    /// development token on localhost. The host refuses to start with it disabled in Production.
    /// </remarks>
    public bool EnableOAuth { get; set; }

    /// <summary>Entra tenant that issues caller tokens.</summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// This server's Application ID URI, which caller tokens must be addressed to, for example
    /// <c>api://{client-id}</c>.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Public base URL advertised in OAuth protected-resource metadata. Leave unset locally to
    /// derive it from the request.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>Scope name clients should request, as advertised in the resource metadata.</summary>
    public string RequiredScope { get; set; } = "onedrive:access";
}
