using System.Text.Json.Serialization;

namespace OneDriveMcp.Server.OAuth.Models;

/// <summary>A client registered through Dynamic Client Registration (RFC 7591).</summary>
public sealed class OAuthClientRegistration
{
    /// <summary>Generated client identifier.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// SHA-256 hash of the client secret, for a confidential client.
    /// </summary>
    /// <remarks>
    /// Only the hash is kept. The plaintext is returned once, at registration, and cannot be
    /// recovered afterwards — a stolen store therefore yields no usable credentials.
    /// </remarks>
    public string? ClientSecretHash { get; init; }

    /// <summary>Human-readable client name.</summary>
    public string? ClientName { get; init; }

    /// <summary>Redirect URIs this client may use.</summary>
    public required IReadOnlyList<string> RedirectUris { get; init; }

    /// <summary>Token endpoint authentication method: <c>none</c> or <c>client_secret_post</c>.</summary>
    public required string TokenEndpointAuthMethod { get; init; }

    /// <summary>When the registration was created.</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>True when the client authenticates with a secret.</summary>
    [JsonIgnore]
    public bool IsConfidential => ClientSecretHash is { Length: > 0 };
}

/// <summary>An issued authorization code, held until it is redeemed.</summary>
public sealed class AuthorizationCode
{
    /// <summary>The code value.</summary>
    public required string Code { get; init; }

    /// <summary>Client the code was issued to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Redirect URI the code was issued for; must match on redemption.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>PKCE challenge, always S256.</summary>
    public required string CodeChallenge { get; init; }

    /// <summary>Authenticated user's stable identifier.</summary>
    public required string SubjectId { get; init; }

    /// <summary>Authenticated user's email, when known.</summary>
    public string? Email { get; init; }

    /// <summary>Scope granted.</summary>
    public string? Scope { get; init; }

    /// <summary>When the code stops being redeemable.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Set the moment the code is redeemed, so a replay is detectable.</summary>
    public bool IsUsed { get; set; }
}

/// <summary>A refresh token, and the family it belongs to.</summary>
public sealed class RefreshTokenEntity
{
    /// <summary>The token value.</summary>
    public required string Token { get; init; }

    /// <summary>Client the token was issued to.</summary>
    public required string ClientId { get; init; }

    /// <summary>User the token acts for.</summary>
    public required string SubjectId { get; init; }

    /// <summary>User's email, when known.</summary>
    public string? Email { get; init; }

    /// <summary>Scope granted.</summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Identifies every token descended from one authorization grant.
    /// </summary>
    /// <remarks>
    /// Rotation means a stolen token and the legitimate one both descend from the same grant.
    /// When a token that has already been rotated is presented again, one of the two parties is
    /// an attacker and there is no way to tell which, so the whole family is revoked.
    /// </remarks>
    public required string FamilyId { get; init; }

    /// <summary>Binds the token to the client that obtained it.</summary>
    public string? Fingerprint { get; init; }

    /// <summary>When the token expires.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Set when the token is rotated away or the family is revoked.</summary>
    public bool IsRevoked { get; set; }
}

/// <summary>A successful token response (RFC 6749 §5.1).</summary>
public sealed class OAuthTokenResponse
{
    /// <summary>The access token.</summary>
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    /// <summary>Always <c>Bearer</c>.</summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";

    /// <summary>Access token lifetime in seconds.</summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    /// <summary>The refresh token.</summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    /// <summary>Granted scope.</summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; init; }
}
