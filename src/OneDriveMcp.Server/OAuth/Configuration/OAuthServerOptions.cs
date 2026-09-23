namespace OneDriveMcp.Server.OAuth.Configuration;

/// <summary>
/// Options for the built-in OAuth 2.1 authorization server, bound from <c>OAuthServer</c>.
/// </summary>
/// <remarks>
/// This server exists because Entra ID does not support Dynamic Client Registration. An MCP
/// client such as Claude or Inspector expects to register itself and obtain a token without a
/// human first creating an app registration, so the server issues its own tokens and uses Entra
/// only to authenticate the user during consent.
/// </remarks>
public sealed class OAuthServerOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "OAuthServer";

    /// <summary>Whether the authorization server endpoints are mapped.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Token issuer. Must be unique to this deployment.
    /// </summary>
    /// <remarks>
    /// Two deployments sharing an issuer would accept each other's tokens, so a token minted for
    /// a test environment would unlock production. Validated at startup for exactly that reason.
    /// </remarks>
    public string? Issuer { get; set; }

    /// <summary>
    /// Public base URL clients reach this server on, used to build the URLs in the discovery
    /// documents. Also the fallback issuer.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>
    /// Hosts accepted in the <c>Host</c> header when deriving the base URL.
    /// </summary>
    /// <remarks>
    /// Without an allow-list, an attacker-controlled <c>Host</c> header would be echoed into the
    /// discovery documents, pointing clients at an authorization endpoint of their choosing.
    /// </remarks>
    public IList<string> AllowedPublicHosts { get; set; } = [];

    /// <summary>Access token lifetime in minutes.</summary>
    public int AccessTokenLifetimeMinutes { get; set; } = 60;

    /// <summary>Refresh token lifetime in hours.</summary>
    public int RefreshTokenLifetimeHours { get; set; } = 24;

    /// <summary>Authorization code lifetime in minutes.</summary>
    public int AuthorizationCodeLifetimeMinutes { get; set; } = 10;

    /// <summary>Client registrations permitted per IP address per minute.</summary>
    public int RegistrationRateLimitPerMinute { get; set; } = 10;

    /// <summary>
    /// Bearer token required to call the registration endpoint.
    /// </summary>
    /// <remarks>
    /// Leaving this unset makes <c>/oauth/register</c> open to anyone. That is defensible on
    /// localhost and nowhere else, so the host warns when it is empty outside Development.
    /// </remarks>
    public string? RegistrationInitialAccessToken { get; set; }

    /// <summary>
    /// Key Vault URI used to persist the signing key.
    /// </summary>
    /// <remarks>
    /// Without it the key is generated in memory, so every restart invalidates every token this
    /// server has issued. Acceptable locally, not in a deployment.
    /// </remarks>
    public string? KeyVaultUri { get; set; }

    /// <summary>Where encrypted client and refresh-token state is persisted.</summary>
    public string? PersistencePath { get; set; }

    /// <summary>Scope granted to clients, and advertised in the discovery document.</summary>
    public string Scope { get; set; } = "onedrive:access";

    /// <summary>Resolves the effective issuer.</summary>
    public string? ResolveIssuer() =>
        string.IsNullOrWhiteSpace(Issuer) ? PublicBaseUrl?.TrimEnd('/') : Issuer.TrimEnd('/');
}
