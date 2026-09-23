using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Helpers;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.OAuth.Endpoints;

/// <summary>The documents a client reads to discover how to authenticate.</summary>
public static class DiscoveryEndpoints
{
    /// <summary>Maps authorization server metadata (RFC 8414) and the JWKS document.</summary>
    public static IEndpointRouteBuilder MapOAuthDiscovery(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet("/.well-known/oauth-authorization-server", (
            HttpContext context,
            IOptions<OAuthServerOptions> options) =>
        {
            var baseUrl = BaseUrlResolver.ResolveOrReject(context, options);

            if (baseUrl is null)
            {
                return Results.BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "The request Host is not an allowed public host."
                });
            }

            // Deliberately not cached: the contents key off the deployment's own configuration,
            // and a stale copy would point clients at the wrong endpoints after a change.
            context.Response.Headers.CacheControl = "no-store";

            return Results.Ok(new
            {
                issuer = options.Value.ResolveIssuer() ?? baseUrl,
                authorization_endpoint = $"{baseUrl}/oauth/authorize",
                token_endpoint = $"{baseUrl}/oauth/token",
                registration_endpoint = $"{baseUrl}/oauth/register",
                revocation_endpoint = $"{baseUrl}/oauth/revoke",
                jwks_uri = $"{baseUrl}/oauth/jwks",
                scopes_supported = new[] { options.Value.Scope },
                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                token_endpoint_auth_methods_supported = new[] { "none", "client_secret_post" },
                revocation_endpoint_auth_methods_supported = new[] { "none", "client_secret_post" },

                // S256 only. Plain PKCE offers no protection against an attacker who can observe
                // the authorization request, which is exactly the threat PKCE exists to address.
                code_challenge_methods_supported = new[] { "S256" }
            });
        })
        .WithName("OAuthAuthorizationServerMetadata")
        .AllowAnonymous();

        endpoints.MapGet("/oauth/jwks", (
            HttpContext context,
            OAuthSigningKeyProvider signingKeyProvider) =>
        {
            var keys = signingKeyProvider.ValidationKeys
                .OfType<RsaSecurityKey>()
                .Select(key =>
                {
                    var parameters = key.Rsa.ExportParameters(includePrivateParameters: false);

                    return new
                    {
                        kty = "RSA",
                        use = "sig",
                        alg = "RS256",
                        kid = key.KeyId,
                        n = Base64UrlEncoder.Encode(parameters.Modulus),
                        e = Base64UrlEncoder.Encode(parameters.Exponent)
                    };
                })
                .ToArray();

            // Cacheable, but briefly: long enough to spare the round trip, short enough that a
            // rotated key is picked up without anyone intervening.
            context.Response.Headers.CacheControl = "public, max-age=300";

            return Results.Ok(new { keys });
        })
        .WithName("OAuthJwks")
        .AllowAnonymous();

        return endpoints;
    }
}
