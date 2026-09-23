using System.IdentityModel.Tokens.Jwt;

namespace OneDriveMcp.Core.Auth;

/// <summary>
/// Reads identity claims out of a bearer token that has <em>already been validated</em> by the
/// authentication middleware.
/// </summary>
/// <remarks>
/// This deliberately does not verify signatures, lifetimes or audiences -- ASP.NET Core's
/// JwtBearer handler owns that. Its only job is to recover the raw claims the OBO flow needs,
/// which the resulting <c>ClaimsPrincipal</c> does not carry in usable form.
/// </remarks>
public static class BearerTokenParser
{
    /// <summary>Issuer prefixes that identify a genuine Microsoft Entra ID token.</summary>
    private static readonly string[] EntraIssuerPrefixes =
    [
        "https://sts.windows.net/",
        "https://login.microsoftonline.com/"
    ];

    /// <summary>
    /// Builds a <see cref="UserCredential"/> from a raw JWT, or returns <see langword="null"/>
    /// if the value is absent or not a readable JWT.
    /// </summary>
    public static UserCredential? TryParse(string? rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return null;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(rawToken))
            {
                return null;
            }

            var jwt = handler.ReadJwtToken(rawToken);

            // oid is stable across token refreshes and app registrations; sub is only unique
            // per (user, application) pair. Prefer oid so the Entra refresh-token store and the
            // Graph token cache key on the same identity the OBO exchange will return.
            var subject = ClaimValue(jwt, "oid") ?? ClaimValue(jwt, "sub");

            return new UserCredential(rawToken, subject, jwt.Issuer, IsEntraIssuer(jwt.Issuer));
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Returns true when the issuer is Entra ID, and the token can therefore be used as an
    /// on-behalf-of assertion. Self-issued tokens from this server's own DCR endpoint return false.
    /// </summary>
    public static bool IsEntraIssuer(string? issuer)
    {
        if (string.IsNullOrEmpty(issuer))
        {
            return false;
        }

        foreach (var prefix in EntraIssuerPrefixes)
        {
            if (issuer.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Strips the <c>Bearer </c> prefix from an Authorization header value.</summary>
    public static string? StripBearerPrefix(string? authorizationHeader)
    {
        const string Prefix = "Bearer ";

        if (string.IsNullOrWhiteSpace(authorizationHeader) ||
            !authorizationHeader.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = authorizationHeader[Prefix.Length..].Trim();
        return token.Length == 0 ? null : token;
    }

    private static string? ClaimValue(JwtSecurityToken jwt, string claimType) =>
        jwt.Payload.TryGetValue(claimType, out var value) ? value?.ToString() : null;
}
