namespace OneDriveMcp.Core.Auth;

/// <summary>
/// Holds the Entra refresh token captured when a user consented, keyed by their object id.
/// </summary>
/// <remarks>
/// <para>
/// This exists to close a gap that is easy to miss. Tokens issued by this server's own
/// authorization server are self-signed, and Entra rejects a self-signed JWT as an on-behalf-of
/// assertion. A server with a service identity could fall back to it; this one is delegated-only,
/// so without a bridge every Graph call from a client that registered through Dynamic Client
/// Registration would fail.
/// </para>
/// <para>
/// The bridge is the refresh token Entra issues during the interactive consent sign-in. It is
/// stored against the user's object id, and redeemed for a Graph token when that user's requests
/// arrive carrying a self-issued token.
/// </para>
/// <para>
/// A refresh token is a long-lived credential for the user's OneDrive, so implementations encrypt
/// it at rest and must never log it.
/// </para>
/// </remarks>
public interface IEntraRefreshTokenStore
{
    /// <summary>Gets the stored refresh token for a user, or null when there is none.</summary>
    /// <param name="subjectId">The user's Entra object id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<string?> GetAsync(string subjectId, CancellationToken cancellationToken);

    /// <summary>
    /// Stores a refresh token for a user, replacing any previous one.
    /// </summary>
    /// <remarks>
    /// Called both when consent is granted and after each redemption, because Entra rotates the
    /// refresh token on use. Failing to store the rotated value would break the next call.
    /// </remarks>
    Task SetAsync(string subjectId, string refreshToken, CancellationToken cancellationToken);

    /// <summary>Removes a user's refresh token, ending the server's delegated access.</summary>
    Task RemoveAsync(string subjectId, CancellationToken cancellationToken);
}
