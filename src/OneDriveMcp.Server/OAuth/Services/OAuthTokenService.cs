using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Models;

namespace OneDriveMcp.Server.OAuth.Services;

/// <summary>Issues and redeems this server's own authorization codes and tokens.</summary>
public sealed class OAuthTokenService(
    IOptions<OAuthServerOptions> options,
    OAuthSigningKeyProvider signingKeyProvider,
    IAccessTokenDenyList denyList,
    ILogger<OAuthTokenService> logger)
{
    // Caps so a flood of unredeemed codes or tokens cannot exhaust memory.
    private const int MaxAuthorizationCodes = 50_000;
    private const int MaxRefreshTokens = 200_000;

    private readonly OAuthServerOptions _options = options?.Value
        ?? throw new ArgumentNullException(nameof(options));

    private readonly OAuthSigningKeyProvider _signingKeyProvider = signingKeyProvider
        ?? throw new ArgumentNullException(nameof(signingKeyProvider));

    private readonly IAccessTokenDenyList _denyList = denyList
        ?? throw new ArgumentNullException(nameof(denyList));

    private readonly ILogger<OAuthTokenService> _logger = logger
        ?? throw new ArgumentNullException(nameof(logger));

    private readonly ConcurrentDictionary<string, AuthorizationCode> _codes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, RefreshTokenEntity> _refreshTokens = new(StringComparer.Ordinal);

    /// <summary>Issues an authorization code for a consented request.</summary>
    public string IssueAuthorizationCode(
        string clientId,
        string redirectUri,
        string codeChallenge,
        string subjectId,
        string? email,
        string? scope)
    {
        if (_codes.Count >= MaxAuthorizationCodes)
        {
            RemoveExpiredCodes();

            if (_codes.Count >= MaxAuthorizationCodes)
            {
                throw new InvalidOperationException("Too many outstanding authorization codes.");
            }
        }

        var code = GenerateSecureToken();

        _codes[code] = new AuthorizationCode
        {
            Code = code,
            ClientId = clientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            SubjectId = subjectId,
            Email = email,
            Scope = scope ?? _options.Scope,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(_options.AuthorizationCodeLifetimeMinutes)
        };

        return code;
    }

    /// <summary>
    /// Validates and consumes an authorization code.
    /// </summary>
    /// <remarks>
    /// The code is removed before anything else is checked, so it cannot be redeemed twice even
    /// if two requests arrive at once and one of them then fails validation.
    /// </remarks>
    public AuthorizationCode? ConsumeAuthorizationCode(
        string code,
        string clientId,
        string redirectUri,
        string codeVerifier)
    {
        if (string.IsNullOrEmpty(code) || !_codes.TryRemove(code, out var entry))
        {
            return null;
        }

        if (entry.IsUsed || entry.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return null;
        }

        if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
        {
            _logger.LogWarning("Authorization code presented by a different client than it was issued to");
            return null;
        }

        if (!string.Equals(entry.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            _logger.LogWarning("Authorization code redeemed with a redirect URI it was not issued for");
            return null;
        }

        if (!ValidatePkceS256(codeVerifier, entry.CodeChallenge))
        {
            _logger.LogWarning("PKCE verification failed for an authorization code");
            return null;
        }

        entry.IsUsed = true;

        return entry;
    }

    /// <summary>
    /// Verifies a PKCE code verifier against its S256 challenge.
    /// </summary>
    /// <remarks>
    /// Compared in constant time: a timing-variable comparison here would leak the challenge one
    /// byte at a time.
    /// </remarks>
    public static bool ValidatePkceS256(string? codeVerifier, string? codeChallenge)
    {
        if (string.IsNullOrEmpty(codeVerifier) || string.IsNullOrEmpty(codeChallenge))
        {
            return false;
        }

        var computed = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computed),
            Encoding.UTF8.GetBytes(codeChallenge));
    }

    /// <summary>Builds a token response for a freshly redeemed authorization code.</summary>
    public OAuthTokenResponse IssueTokens(
        string clientId,
        string subjectId,
        string? email,
        string? scope,
        string? fingerprint)
    {
        var familyId = Guid.NewGuid().ToString("N");

        return IssueTokens(clientId, subjectId, email, scope, fingerprint, familyId);
    }

    /// <summary>
    /// Redeems a refresh token, rotating it.
    /// </summary>
    /// <remarks>
    /// Reuse of an already-rotated token means either the legitimate client or an attacker is
    /// replaying it, and there is no way to tell which. Revoking the whole family ends both
    /// sessions, which is the point: the legitimate user re-authenticates, and the attacker is cut
    /// off. A fingerprint mismatch is treated the same way.
    /// </remarks>
    public OAuthTokenResponse? RedeemRefreshToken(
        string refreshToken,
        string clientId,
        string? fingerprint)
    {
        if (string.IsNullOrEmpty(refreshToken) ||
            !_refreshTokens.TryGetValue(refreshToken, out var entry))
        {
            return null;
        }

        if (entry.IsRevoked)
        {
            RevokeFamily(entry.FamilyId, "a revoked refresh token was presented again");
            return null;
        }

        if (entry.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return null;
        }

        if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
        {
            return null;
        }

        if (entry.Fingerprint is { Length: > 0 } expected &&
            !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected),
                Encoding.UTF8.GetBytes(fingerprint ?? string.Empty)))
        {
            RevokeFamily(entry.FamilyId, "refresh token presented from a different client fingerprint");
            return null;
        }

        entry.IsRevoked = true;

        return IssueTokens(
            entry.ClientId, entry.SubjectId, entry.Email, entry.Scope, fingerprint, entry.FamilyId);
    }

    /// <summary>
    /// Revokes a refresh token and everything else descended from the same grant.
    /// </summary>
    /// <returns>
    /// The subject the token belonged to, so the caller can also release the delegated Microsoft
    /// access held for that user; null when the token was not recognised.
    /// </returns>
    public string? RevokeRefreshToken(string refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken) ||
            !_refreshTokens.TryGetValue(refreshToken, out var entry))
        {
            return null;
        }

        RevokeFamily(entry.FamilyId, "explicit revocation");

        return entry.SubjectId;
    }

    /// <summary>Revokes an access token by adding it to the deny list until it would expire.</summary>
    public void RevokeAccessToken(string accessToken)
    {
        if (string.IsNullOrEmpty(accessToken))
        {
            return;
        }

        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(_options.AccessTokenLifetimeMinutes);

        try
        {
            var handler = new JwtSecurityTokenHandler();

            if (handler.CanReadToken(accessToken))
            {
                expiresAt = new DateTimeOffset(handler.ReadJwtToken(accessToken).ValidTo, TimeSpan.Zero);
            }
        }
        catch (ArgumentException)
        {
            // Not readable; the configured lifetime is a safe upper bound.
        }

        _denyList.Revoke(accessToken, expiresAt);
    }

    /// <summary>
    /// Binds a token to the client that obtained it.
    /// </summary>
    /// <remarks>
    /// A coarse signal, not an authenticator: it raises the cost of replaying a stolen refresh
    /// token from elsewhere without being something a determined attacker cannot reproduce.
    /// </remarks>
    public static string ComputeFingerprint(string? ipAddress, string? userAgent) =>
        Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{ipAddress ?? "unknown"}|{userAgent ?? "unknown"}")));

    /// <summary>Current refresh tokens, for persistence.</summary>
    public IReadOnlyCollection<RefreshTokenEntity> SnapshotRefreshTokens() =>
        _refreshTokens.Values.ToArray();

    /// <summary>Restores persisted refresh tokens.</summary>
    public void RestoreRefreshTokens(IEnumerable<RefreshTokenEntity> tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        foreach (var token in tokens.Where(t => t.ExpiresAt > DateTimeOffset.UtcNow))
        {
            _refreshTokens[token.Token] = token;
        }
    }

    private OAuthTokenResponse IssueTokens(
        string clientId,
        string subjectId,
        string? email,
        string? scope,
        string? fingerprint,
        string familyId)
    {
        var accessToken = CreateAccessToken(clientId, subjectId, email, scope, familyId);
        var refreshToken = GenerateSecureToken();

        if (_refreshTokens.Count >= MaxRefreshTokens)
        {
            RemoveExpiredRefreshTokens();
        }

        _refreshTokens[refreshToken] = new RefreshTokenEntity
        {
            Token = refreshToken,
            ClientId = clientId,
            SubjectId = subjectId,
            Email = email,
            Scope = scope,
            FamilyId = familyId,
            Fingerprint = fingerprint,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(_options.RefreshTokenLifetimeHours)
        };

        return new OAuthTokenResponse
        {
            AccessToken = accessToken,
            ExpiresIn = _options.AccessTokenLifetimeMinutes * 60,
            RefreshToken = refreshToken,
            Scope = scope
        };
    }

    private string CreateAccessToken(
        string clientId,
        string subjectId,
        string? email,
        string? scope,
        string familyId)
    {
        var issuer = _options.ResolveIssuer()
            ?? throw new InvalidOperationException("OAuthServer:Issuer is not configured.");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subjectId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("client_id", clientId),

            // Identifies the grant this token descends from, so detecting a stolen refresh token
            // can invalidate the access tokens already issued from the same grant rather than
            // leaving them usable until they expire.
            new(FamilyClaim, familyId)
        };

        if (!string.IsNullOrEmpty(email))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, email));
        }

        if (!string.IsNullOrEmpty(scope))
        {
            claims.Add(new Claim("scope", scope));
        }

        var now = DateTime.UtcNow;

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = issuer,

            // Audience equals issuer: this server is both the authority that mints the token and
            // the only resource meant to accept it.
            Audience = issuer,
            NotBefore = now,
            Expires = now.AddMinutes(_options.AccessTokenLifetimeMinutes),
            SigningCredentials = _signingKeyProvider.SigningCredentials
        };

        var handler = new JwtSecurityTokenHandler();

        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    /// <summary>Claim carrying the grant a token descends from.</summary>
    public const string FamilyClaim = "family_id";

    private void RevokeFamily(string familyId, string reason)
    {
        // Access tokens outlive this call unless they are refused explicitly. Without it the
        // holder of a stolen token keeps their access for the remainder of its lifetime, which
        // is precisely the window reuse detection exists to close.
        _denyList.RevokeFamily(
            familyId, DateTimeOffset.UtcNow.AddMinutes(_options.AccessTokenLifetimeMinutes));

        var revoked = 0;

        foreach (var entry in _refreshTokens.Values)
        {
            if (string.Equals(entry.FamilyId, familyId, StringComparison.Ordinal) && !entry.IsRevoked)
            {
                entry.IsRevoked = true;
                revoked++;
            }
        }

        _logger.LogWarning(
            "Revoked {Count} refresh token(s) in family {FamilyId}: {Reason}",
            revoked, familyId, reason);
    }

    private void RemoveExpiredCodes()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (code, entry) in _codes)
        {
            if (entry.ExpiresAt <= now)
            {
                _codes.TryRemove(code, out _);
            }
        }
    }

    private void RemoveExpiredRefreshTokens()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (token, entry) in _refreshTokens)
        {
            if (entry.ExpiresAt <= now)
            {
                _refreshTokens.TryRemove(token, out _);
            }
        }
    }

    private static string GenerateSecureToken() =>
        Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
