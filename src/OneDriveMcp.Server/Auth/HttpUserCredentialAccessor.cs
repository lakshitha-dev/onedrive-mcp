using Microsoft.AspNetCore.Http;
using OneDriveMcp.Core.Auth;

namespace OneDriveMcp.Server.Auth;

/// <summary>
/// Reads the caller's credential from the HTTP request currently in flight.
/// </summary>
/// <remarks>
/// Registered as a singleton over the singleton <c>IHttpContextAccessor</c>. Each MCP tool call
/// arrives as its own POST, and with <c>PerSessionExecutionContext == false</c> (the SDK default)
/// the accessor resolves to that POST -- not to the long-finished <c>initialize</c> request.
/// That is what makes a per-call token read correct here without any AsyncLocal plumbing.
/// </remarks>
public sealed class HttpUserCredentialAccessor(IHttpContextAccessor httpContextAccessor)
    : IUserCredentialAccessor
{
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor
        ?? throw new ArgumentNullException(nameof(httpContextAccessor));

    /// <inheritdoc />
    public UserCredential? Current
    {
        get
        {
            var context = _httpContextAccessor.HttpContext;
            if (context is null)
            {
                return null;
            }

            var header = context.Request.Headers.Authorization.FirstOrDefault();
            var rawToken = BearerTokenParser.StripBearerPrefix(header);

            return BearerTokenParser.TryParse(rawToken);
        }
    }
}
