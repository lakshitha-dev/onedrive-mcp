using System.ComponentModel;
using ModelContextProtocol.Server;
using OneDriveMcp.Core.Auth;

namespace OneDriveMcp.Core.Tools;

/// <summary>Result of <c>onedrive_auth_status</c>.</summary>
/// <param name="Authenticated">Whether a bearer token was present on the current request.</param>
/// <param name="Subject">The caller's Entra object id, when known.</param>
/// <param name="Issuer">The token issuer.</param>
/// <param name="TokenKind">
/// <c>entra</c> for a genuine Entra token (usable for on-behalf-of), <c>self-issued</c> for one
/// minted by this server's Dynamic Client Registration endpoint, or <c>none</c>.
/// </param>
/// <param name="CanCallGraphDirectly">
/// True when the credential can be exchanged for a Graph token by on-behalf-of without needing
/// the stored Entra refresh token.
/// </param>
public sealed record AuthStatus(
    bool Authenticated,
    string? Subject,
    string? Issuer,
    string TokenKind,
    bool CanCallGraphDirectly);

/// <summary>
/// Diagnostics that do not touch Microsoft Graph.
/// </summary>
/// <remarks>
/// <para>
/// Every dependency of a tool class must be a singleton. The SDK constructs a new instance of
/// the class for each invocation, resolving it from the message context's service provider,
/// which for a stateful HTTP session derives from the <c>initialize</c> request whose ASP.NET
/// scope is long gone by the time a tool runs. Singletons sidestep that entirely.
/// </para>
/// <para>
/// <c>onedrive_auth_status</c> is also how we verify that claim: it reports the credential seen
/// by the <em>current</em> request, so calling it twice with different tokens on one MCP session
/// proves the accessor is not pinned to session start.
/// </para>
/// </remarks>
[McpServerToolType]
public sealed class DiagnosticsTools(IUserCredentialAccessor credentialAccessor)
{
    private readonly IUserCredentialAccessor _credentialAccessor = credentialAccessor
        ?? throw new ArgumentNullException(nameof(credentialAccessor));

    /// <summary>Reports how the current caller is authenticated.</summary>
    [McpServerTool(
        Name = "onedrive_auth_status",
        Title = "Check OneDrive authentication status",
        ReadOnly = true,
        Idempotent = true,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Report how the current caller is authenticated to this OneDrive server, without " +
        "calling Microsoft Graph. Use this to diagnose authentication problems before " +
        "concluding that a file operation failed for some other reason.")]
    public AuthStatus GetAuthStatus()
    {
        var credential = _credentialAccessor.Current;

        if (credential is null)
        {
            return new AuthStatus(
                Authenticated: false,
                Subject: null,
                Issuer: null,
                TokenKind: "none",
                CanCallGraphDirectly: false);
        }

        return new AuthStatus(
            Authenticated: true,
            Subject: credential.Subject,
            Issuer: credential.Issuer,
            TokenKind: credential.IsEntra ? "entra" : "self-issued",
            CanCallGraphDirectly: credential.IsEntra);
    }
}
