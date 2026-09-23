using System.Security.Cryptography;
using System.Text;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Server.OAuth.Helpers;
using OneDriveMcp.Server.OAuth.Models;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.OAuth.Endpoints;

/// <summary>Exchanges an authorization code or refresh token for an access token.</summary>
public static class TokenEndpoint
{
    /// <summary>Maps <c>POST /oauth/token</c>.</summary>
    public static IEndpointRouteBuilder MapOAuthToken(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost("/oauth/token", async (
            HttpContext context,
            OAuthTokenService tokenService,
            IOAuthClientStore clientStore,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger(typeof(TokenEndpoint));

            if (!context.Request.HasFormContentType)
            {
                return Invalid("invalid_request", "The token endpoint expects a form-encoded body.");
            }

            var form = await context.Request.ReadFormAsync();

            // Never cached anywhere: the response body is a credential.
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";

            var grantType = form["grant_type"].ToString();
            var clientId = form["client_id"].ToString();

            if (string.IsNullOrEmpty(clientId))
            {
                return Invalid("invalid_request", "client_id is required.");
            }

            var client = clientStore.Find(clientId);

            if (client is null)
            {
                return Invalid("invalid_client", "Unknown client_id.");
            }

            if (client.IsConfidential && !IsClientSecretValid(client, form["client_secret"].ToString()))
            {
                logger.LogWarning("Client {ClientId} presented an invalid secret", clientId);

                return Invalid("invalid_client", "Client authentication failed.");
            }

            var fingerprint = OAuthTokenService.ComputeFingerprint(
                ClientIpResolver.Resolve(context),
                context.Request.Headers.UserAgent.ToString());

            return grantType switch
            {
                "authorization_code" => HandleAuthorizationCode(form, clientId, fingerprint, tokenService, logger),
                "refresh_token" => HandleRefreshToken(form, clientId, fingerprint, tokenService, logger),
                _ => Invalid(
                    "unsupported_grant_type",
                    "Supported grant types are 'authorization_code' and 'refresh_token'.")
            };
        })
        .WithName("OAuthToken")
        .AllowAnonymous();

        return endpoints;
    }

    private static IResult HandleAuthorizationCode(
        IFormCollection form,
        string clientId,
        string fingerprint,
        OAuthTokenService tokenService,
        ILogger logger)
    {
        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        if (string.IsNullOrEmpty(code) ||
            string.IsNullOrEmpty(redirectUri) ||
            string.IsNullOrEmpty(codeVerifier))
        {
            return Invalid(
                "invalid_request",
                "code, redirect_uri and code_verifier are all required for the authorization_code grant.");
        }

        var consumed = tokenService.ConsumeAuthorizationCode(code, clientId, redirectUri, codeVerifier);

        if (consumed is null)
        {
            // Deliberately uniform: distinguishing "expired" from "wrong verifier" from "already
            // used" would tell an attacker which part of a guess was correct.
            logger.LogWarning("Authorization code redemption failed for client {ClientId}", clientId);

            return Invalid("invalid_grant", "The authorization code is invalid, expired or already used.");
        }

        var response = tokenService.IssueTokens(
            clientId, consumed.SubjectId, consumed.Email, consumed.Scope, fingerprint);

        return Results.Ok(response);
    }

    private static IResult HandleRefreshToken(
        IFormCollection form,
        string clientId,
        string fingerprint,
        OAuthTokenService tokenService,
        ILogger logger)
    {
        var refreshToken = form["refresh_token"].ToString();

        if (string.IsNullOrEmpty(refreshToken))
        {
            return Invalid("invalid_request", "refresh_token is required.");
        }

        var response = tokenService.RedeemRefreshToken(refreshToken, clientId, fingerprint);

        if (response is null)
        {
            logger.LogWarning("Refresh token redemption failed for client {ClientId}", clientId);

            return Invalid("invalid_grant", "The refresh token is invalid, expired or has been revoked.");
        }

        return Results.Ok(response);
    }

    private static bool IsClientSecretValid(OAuthClientRegistration client, string? presented)
    {
        if (string.IsNullOrEmpty(presented) || client.ClientSecretHash is not { Length: > 0 } expected)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(ClientRegistrationEndpoint.HashSecret(presented)),
            Encoding.UTF8.GetBytes(expected));
    }

    private static IResult Invalid(string error, string description) =>
        Results.BadRequest(new { error, error_description = description });
}

/// <summary>Revokes a token (RFC 7009).</summary>
public static class RevocationEndpoint
{
    /// <summary>Largest token this endpoint will even look at.</summary>
    private const int MaxTokenLength = 32 * 1024;

    /// <summary>Maps <c>POST /oauth/revoke</c>.</summary>
    public static IEndpointRouteBuilder MapOAuthRevocation(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost("/oauth/revoke", async (
            HttpContext context,
            OAuthTokenService tokenService,
            IEntraRefreshTokenStore entraRefreshTokens,
            OAuthStatePersistence statePersistence) =>
        {
            if (!context.Request.HasFormContentType)
            {
                // RFC 7009 wants 200 regardless, so a caller cannot probe which tokens exist.
                return Results.Ok();
            }

            var form = await context.Request.ReadFormAsync();
            var token = form["token"].ToString();

            context.Response.Headers.CacheControl = "no-store";

            if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
            {
                return Results.Ok();
            }

            // A JWT is one of ours: an access token. Anything else is treated as a refresh token.
            // No client authentication is required to revoke an access token, because presenting
            // the token is itself proof of holding it, and the safe outcome of a spurious call is
            // that a credential stops working.
            if (token.Count(c => c == '.') == 2)
            {
                tokenService.RevokeAccessToken(token);
            }
            else if (tokenService.RevokeRefreshToken(token) is { Length: > 0 } subjectId)
            {
                // Releasing this server's own token is not enough: the delegated Microsoft access
                // captured at consent would otherwise remain usable by any token still issued for
                // that user. Revoking means revoking.
                await entraRefreshTokens.RemoveAsync(subjectId, context.RequestAborted);
            }

            // Written out now rather than at the next timer tick. Losing thirty seconds of client
            // registrations to a crash is a nuisance; losing a revocation means the token the
            // caller just revoked starts working again after the next restart.
            await statePersistence.FlushAsync(context.RequestAborted);

            return Results.Ok();
        })
        .WithName("OAuthRevocation")
        .AllowAnonymous();

        return endpoints;
    }
}
