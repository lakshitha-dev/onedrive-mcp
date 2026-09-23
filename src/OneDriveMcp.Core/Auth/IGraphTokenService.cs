namespace OneDriveMcp.Core.Auth;

/// <summary>
/// Supplies a Microsoft Graph access token for the caller of the current request.
/// </summary>
/// <remarks>
/// Implementations resolve the credential from <see cref="IUserCredentialAccessor"/> and exchange
/// it. An Entra token is exchanged by the on-behalf-of flow; a token this server issued itself
/// through Dynamic Client Registration is self-signed, which Entra rejects as an OBO assertion,
/// so it has to be resolved through a stored Entra refresh token instead.
/// </remarks>
public interface IGraphTokenService
{
    /// <summary>Gets a Graph access token for the current caller.</summary>
    /// <exception cref="AuthenticationRequiredException">
    /// No usable credential is available and the caller must authenticate again.
    /// </exception>
    /// <exception cref="TokenExchangeFailedException">The exchange itself failed.</exception>
    Task<string> GetGraphTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The caller has no usable credential, so the client must restart the OAuth flow.
/// </summary>
/// <remarks>
/// This must surface to the client as HTTP 401 with a <c>WWW-Authenticate</c> challenge. Reporting
/// it only as a failed tool call leaves the client with no way to know it should re-authenticate.
/// </remarks>
public sealed class AuthenticationRequiredException(string message, Exception? innerException = null)
    : Exception(message, innerException);

/// <summary>
/// A token exchange against Entra failed.
/// </summary>
/// <param name="message">Description of the failure.</param>
/// <param name="errorCode">The <c>AADSTS</c> code, when one could be extracted.</param>
/// <param name="innerException">The underlying failure, if any.</param>
public sealed class TokenExchangeFailedException(
    string message,
    string? errorCode = null,
    Exception? innerException = null)
    : Exception(message, innerException)
{
    /// <summary>The Entra <c>AADSTS</c> error code, when known.</summary>
    public string? ErrorCode { get; } = errorCode;
}
