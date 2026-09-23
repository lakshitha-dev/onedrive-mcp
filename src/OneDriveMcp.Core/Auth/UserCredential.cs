namespace OneDriveMcp.Core.Auth;

/// <summary>
/// The caller's bearer credential for a single tool invocation.
/// </summary>
/// <param name="RawToken">
/// The raw JWT, exactly as it arrived on the Authorization header. The raw string is
/// required because an Entra token is used verbatim as the on-behalf-of assertion --
/// a <see cref="System.Security.Claims.ClaimsPrincipal"/> is not sufficient.
/// </param>
/// <param name="Subject">The <c>oid</c> claim if present, otherwise <c>sub</c>.</param>
/// <param name="Issuer">The <c>iss</c> claim.</param>
/// <param name="IsEntra">
/// True when the issuer is Microsoft Entra ID, meaning the token can be exchanged via the
/// on-behalf-of flow. False for tokens this server issued itself through Dynamic Client
/// Registration; those are self-signed and Entra rejects them as an OBO assertion, so they
/// must go through the stored Entra refresh token instead.
/// </param>
public sealed record UserCredential(
    string RawToken,
    string? Subject,
    string? Issuer,
    bool IsEntra);

/// <summary>
/// Supplies the credential belonging to the HTTP request currently being served.
/// </summary>
/// <remarks>
/// <para>
/// Under the Streamable HTTP transport every tool call is its own POST, so the credential
/// must be read per request rather than captured once when the MCP session is initialised.
/// </para>
/// <para>
/// The server-side implementation reads it from <c>IHttpContextAccessor</c>. That is only
/// correct while <c>HttpServerTransportOptions.PerSessionExecutionContext</c> stays at its
/// default of <see langword="false"/>; setting it true gives the whole session one execution
/// context and, per the SDK documentation, "prevents you from using IHttpContextAccessor in
/// handlers". A test asserts the default so that flipping it cannot silently break every tool.
/// </para>
/// </remarks>
public interface IUserCredentialAccessor
{
    /// <summary>
    /// Gets the current request's credential, or <see langword="null"/> when the caller is
    /// unauthenticated or there is no request in scope.
    /// </summary>
    UserCredential? Current { get; }
}
