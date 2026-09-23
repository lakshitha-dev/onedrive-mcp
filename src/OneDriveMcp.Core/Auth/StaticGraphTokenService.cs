namespace OneDriveMcp.Core.Auth;

/// <summary>
/// Returns a fixed Graph access token.
/// </summary>
/// <remarks>
/// <para>
/// This exists so the Graph client and every tool can be exercised end to end before any OAuth
/// machinery is in place: paste a token from Graph Explorer into <c>Dev:GraphAccessToken</c> and
/// the whole tool surface works. It is the reason the Graph layer can be proven independently of
/// the authorization server, which is the slowest and least informative part to build.
/// </para>
/// <para>
/// Registered only outside Production, and the host logs a warning when it is active. It ignores
/// the caller's identity entirely, so it must never serve real users.
/// </para>
/// </remarks>
public sealed class StaticGraphTokenService(string? accessToken) : IGraphTokenService
{
    private readonly string? _accessToken = accessToken;

    /// <inheritdoc />
    public Task<string> GetGraphTokenAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_accessToken))
        {
            throw new AuthenticationRequiredException(
                "No Graph token is configured. Set 'Dev:GraphAccessToken' to a token from " +
                "Graph Explorer (https://developer.microsoft.com/graph/graph-explorer) with the " +
                "Files.ReadWrite and User.Read scopes consented.");
        }

        return Task.FromResult(_accessToken);
    }
}
