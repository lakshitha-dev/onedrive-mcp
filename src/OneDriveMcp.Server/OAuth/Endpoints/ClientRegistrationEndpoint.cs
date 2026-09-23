using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Helpers;
using OneDriveMcp.Server.OAuth.Models;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.OAuth.Endpoints;

/// <summary>Dynamic Client Registration request body (RFC 7591).</summary>
public sealed class ClientRegistrationRequest
{
    /// <summary>Human-readable client name.</summary>
    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    /// <summary>Redirect URIs the client will use.</summary>
    [JsonPropertyName("redirect_uris")]
    public IReadOnlyList<string>? RedirectUris { get; init; }

    /// <summary>Grant types requested.</summary>
    [JsonPropertyName("grant_types")]
    public IReadOnlyList<string>? GrantTypes { get; init; }

    /// <summary>Requested token endpoint authentication method.</summary>
    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }
}

/// <summary>
/// Lets an MCP client register itself.
/// </summary>
/// <remarks>
/// This endpoint is the whole reason the server issues its own tokens: Entra ID does not support
/// Dynamic Client Registration, so a client such as Claude or Inspector could not otherwise
/// obtain credentials without someone first creating an app registration by hand.
/// </remarks>
public static class ClientRegistrationEndpoint
{
    private const int MaxClientNameLength = 256;
    private const int MaxRedirectUris = 10;
    private const int MaxRedirectUriLength = 2048;

    /// <summary>Maps <c>POST /oauth/register</c>.</summary>
    public static IEndpointRouteBuilder MapClientRegistration(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost("/oauth/register", (
            HttpContext context,
            ClientRegistrationRequest request,
            IOptions<OAuthServerOptions> options,
            IOAuthClientStore clientStore,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger(typeof(ClientRegistrationEndpoint));

            // An initial access token turns open registration into invite-only. Without one
            // anybody can register a client, which is defensible on localhost and nowhere else.
            var requiredToken = options.Value.RegistrationInitialAccessToken;

            if (!string.IsNullOrEmpty(requiredToken) && !HasValidInitialAccessToken(context, requiredToken))
            {
                return Results.Json(
                    new { error = "invalid_token", error_description = "A valid initial access token is required." },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            if (Validate(request) is { } validationError)
            {
                return Results.BadRequest(new
                {
                    error = "invalid_client_metadata",
                    error_description = validationError
                });
            }

            var authMethod = string.IsNullOrWhiteSpace(request.TokenEndpointAuthMethod)
                ? "none"
                : request.TokenEndpointAuthMethod;

            string? clientSecret = null;
            string? clientSecretHash = null;

            if (string.Equals(authMethod, "client_secret_post", StringComparison.Ordinal))
            {
                clientSecret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

                // Only the hash is kept. The plaintext is returned once and is unrecoverable
                // afterwards, so a compromised store yields nothing usable.
                clientSecretHash = HashSecret(clientSecret);
            }

            var registration = new OAuthClientRegistration
            {
                ClientId = Guid.NewGuid().ToString("N"),
                ClientSecretHash = clientSecretHash,
                ClientName = request.ClientName,
                RedirectUris = request.RedirectUris!,
                TokenEndpointAuthMethod = authMethod
            };

            clientStore.Add(registration);

            logger.LogInformation(
                "Registered OAuth client {ClientId} ({ClientName}) from {ClientIp}",
                registration.ClientId,
                registration.ClientName ?? "unnamed",
                ClientIpResolver.Resolve(context));

            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";

            // Only the fields RFC 7591 defines. Internal bookkeeping stays internal.
            return Results.Created((string?)null, new
            {
                client_id = registration.ClientId,
                client_secret = clientSecret,
                client_name = registration.ClientName,
                redirect_uris = registration.RedirectUris,
                grant_types = new[] { "authorization_code", "refresh_token" },
                token_endpoint_auth_method = registration.TokenEndpointAuthMethod
            });
        })
        .WithName("OAuthClientRegistration")
        .AllowAnonymous();

        return endpoints;
    }

    /// <summary>Hashes a client secret for storage and comparison.</summary>
    public static string HashSecret(string secret) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private static bool HasValidInitialAccessToken(HttpContext context, string expected)
    {
        var header = context.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrWhiteSpace(header) ||
            !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var presented = header["Bearer ".Length..].Trim();

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presented),
            Encoding.UTF8.GetBytes(expected));
    }

    /// <summary>Validates the registration request, returning an error description or null.</summary>
    private static string? Validate(ClientRegistrationRequest request)
    {
        if (request.ClientName is { Length: > MaxClientNameLength })
        {
            return $"client_name must be at most {MaxClientNameLength} characters.";
        }

        if (request.RedirectUris is null || request.RedirectUris.Count == 0)
        {
            return "redirect_uris is required and must contain at least one URI.";
        }

        if (request.RedirectUris.Count > MaxRedirectUris)
        {
            return $"redirect_uris must contain at most {MaxRedirectUris} entries.";
        }

        foreach (var redirectUri in request.RedirectUris)
        {
            if (string.IsNullOrWhiteSpace(redirectUri) || redirectUri.Length > MaxRedirectUriLength)
            {
                return "Each redirect_uri must be non-empty and at most 2048 characters.";
            }

            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
            {
                return $"redirect_uri '{redirectUri}' is not an absolute URI.";
            }

            // HTTPS everywhere except loopback, where a local client cannot obtain a certificate
            // and there is no network to intercept.
            var isLoopback = uri.IsLoopback
                || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase);

            if (uri.Scheme != Uri.UriSchemeHttps && !isLoopback)
            {
                return $"redirect_uri '{redirectUri}' must use HTTPS unless it is a loopback address.";
            }

            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                return $"redirect_uri '{redirectUri}' must not contain a fragment.";
            }
        }

        if (request.GrantTypes is { Count: > 0 } &&
            !request.GrantTypes.Contains("authorization_code", StringComparer.Ordinal))
        {
            return "grant_types must include 'authorization_code'.";
        }

        if (request.TokenEndpointAuthMethod is { Length: > 0 } method &&
            method is not ("none" or "client_secret_post"))
        {
            return "token_endpoint_auth_method must be 'none' or 'client_secret_post'.";
        }

        return null;
    }
}
