using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OneDriveMcp.Core.Configuration;

namespace OneDriveMcp.Core.Auth;

/// <summary>
/// Exchanges the caller's Entra token for a Microsoft Graph token using the OAuth 2.0
/// on-behalf-of flow, and caches the result per user.
/// </summary>
/// <remarks>
/// <para>
/// Ported from the gateway's OneDrive plugin, whose caching design is worth keeping: entries are
/// keyed on a hash of the incoming assertion, so a cache entry is inherently scoped to one user's
/// one token and a collision cannot leak another user's drive.
/// </para>
/// <para>
/// A secondary index from the user's object id to their latest cache key lets a rotated caller
/// token be served by redeeming the stored refresh token, instead of paying for a fresh
/// on-behalf-of round trip on every rotation.
/// </para>
/// </remarks>
public sealed partial class OboGraphTokenService : IGraphTokenService, IDisposable
{
    /// <summary>Renew slightly before actual expiry so a token is never used as it lapses.</summary>
    private static readonly TimeSpan ExpiryBuffer = TimeSpan.FromMinutes(2);

    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly HttpClient _httpClient;
    private readonly IUserCredentialAccessor _credentialAccessor;
    private readonly IEntraRefreshTokenStore _entraRefreshTokens;
    private readonly OneDriveOptions _options;
    private readonly ILogger<OboGraphTokenService> _logger;

    private readonly ConcurrentDictionary<string, CachedToken> _tokenCache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _latestKeyByUser = new(StringComparer.Ordinal);
    private readonly Timer _cleanupTimer;

    private bool _disposed;

    /// <summary>Creates a new instance.</summary>
    public OboGraphTokenService(
        HttpClient httpClient,
        IUserCredentialAccessor credentialAccessor,
        IEntraRefreshTokenStore entraRefreshTokens,
        IOptions<OneDriveOptions> options,
        ILogger<OboGraphTokenService> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _credentialAccessor = credentialAccessor ?? throw new ArgumentNullException(nameof(credentialAccessor));
        _entraRefreshTokens = entraRefreshTokens ?? throw new ArgumentNullException(nameof(entraRefreshTokens));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _cleanupTimer = new Timer(_ => RemoveExpired(), null, CleanupInterval, CleanupInterval);
    }

    /// <summary>Matches the <c>AADSTS</c> code in an Entra error response.</summary>
    [GeneratedRegex(@"AADSTS\d+")]
    private static partial Regex AadstsCode();

    /// <inheritdoc />
    public async Task<string> GetGraphTokenAsync(CancellationToken cancellationToken)
    {
        var credential = _credentialAccessor.Current
            ?? throw new AuthenticationRequiredException(
                "No credential was presented with this request. Sign in and try again.");

        EnsureConfigured();

        if (!credential.IsEntra)
        {
            // A token this server issued through Dynamic Client Registration is self-signed, and
            // Entra rejects a self-signed JWT as an on-behalf-of assertion. The delegated access
            // captured during consent is redeemed instead.
            return await GetTokenForSelfIssuedCredentialAsync(credential, cancellationToken);
        }

        EnsureAssertionIsUsable(credential);

        var cacheKey = ComputeCacheKey(credential.RawToken);

        if (_tokenCache.TryGetValue(cacheKey, out var cached) && !cached.IsExpired)
        {
            return cached.AccessToken;
        }

        // The caller's token may simply have rotated. Redeeming the refresh token stored against
        // their previous entry avoids a full on-behalf-of exchange.
        if (credential.Subject is { Length: > 0 } subject
            && _latestKeyByUser.TryGetValue(subject, out var previousKey)
            && _tokenCache.TryGetValue(previousKey, out var previous)
            && previous.RefreshToken is { Length: > 0 } refreshToken)
        {
            var refreshed = await TryRefreshAsync(refreshToken, cacheKey, subject, cancellationToken);

            if (refreshed is not null)
            {
                return refreshed;
            }

            _logger.LogInformation(
                "Refresh token exchange failed for user {Subject}; falling back to a new on-behalf-of exchange",
                subject);
        }

        var response = await ExchangeAsync(credential.RawToken, cancellationToken);

        Store(cacheKey, credential.Subject, response);

        return response.AccessToken;
    }

    /// <summary>
    /// Resolves a Graph token for a caller presenting a token this server issued itself.
    /// </summary>
    /// <remarks>
    /// Keyed on the subject, which for a self-issued token is the Entra object id copied in when
    /// the authorization code was granted. That is what lets the two identities line up.
    /// </remarks>
    private async Task<string> GetTokenForSelfIssuedCredentialAsync(
        UserCredential credential,
        CancellationToken cancellationToken)
    {
        if (credential.Subject is not { Length: > 0 } subject)
        {
            throw new AuthenticationRequiredException(
                "The access token carries no subject, so the server cannot tell which account it " +
                "acts for. Sign in again.");
        }

        var cacheKey = ComputeCacheKey(credential.RawToken);

        if (_tokenCache.TryGetValue(cacheKey, out var cached) && !cached.IsExpired)
        {
            return cached.AccessToken;
        }

        var storedRefreshToken = await _entraRefreshTokens.GetAsync(subject, cancellationToken);

        if (storedRefreshToken is null)
        {
            // Authenticated, but this server holds no delegated access for them. Interactive
            // sign-in is the only way to obtain it, so say so rather than failing obscurely.
            throw new AuthenticationRequiredException(
                "This server does not hold Microsoft OneDrive access for your account. Sign in " +
                "again through the authorization page to grant it.");
        }

        TokenResponse response;

        try
        {
            response = await PerformRefreshAsync(storedRefreshToken, cancellationToken);
        }
        catch (TokenExchangeFailedException exception)
        {
            // The stored token is spent or was revoked. Dropping it means the next request asks
            // for a fresh sign-in rather than retrying something that cannot work.
            await _entraRefreshTokens.RemoveAsync(subject, cancellationToken);

            _logger.LogInformation(
                "Stored Entra refresh token for {Subject} was rejected ({ErrorCode}); it has been discarded",
                subject, exception.ErrorCode ?? "(no code)");

            throw new AuthenticationRequiredException(
                "Your saved Microsoft sign-in has expired. Sign in again through the " +
                "authorization page.", exception);
        }

        // Entra rotates the refresh token on use, so the new one has to replace the old or the
        // next request would present a token that has already been spent.
        if (response.RefreshToken is { Length: > 0 } rotated)
        {
            await _entraRefreshTokens.SetAsync(subject, rotated, cancellationToken);
        }

        Store(cacheKey, subject, response);

        return response.AccessToken;
    }

    // ------------------------------------------------------------------ exchange

    private async Task<TokenResponse> ExchangeAsync(string assertion, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ["client_id"] = _options.OboClientId!,
            ["client_secret"] = _options.OboClientSecret!,
            ["assertion"] = assertion,
            ["scope"] = ResolveScope(),
            ["requested_token_use"] = "on_behalf_of"
        };

        return await PostAsync(form, "on-behalf-of", cancellationToken);
    }

    /// <summary>
    /// Redeems a refresh token for a Graph access token.
    /// </summary>
    /// <remarks>
    /// Shared by both paths that need it: recovering from a rotated caller token, and redeeming
    /// the delegated access stored for a caller holding a self-issued token.
    /// </remarks>
    private Task<TokenResponse> PerformRefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = _options.OboClientId!,
            ["client_secret"] = _options.OboClientSecret!,
            ["refresh_token"] = refreshToken,
            ["scope"] = ResolveScope()
        };

        return PostAsync(form, "refresh_token", cancellationToken);
    }

    private async Task<string?> TryRefreshAsync(
        string refreshToken,
        string cacheKey,
        string subject,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await PerformRefreshAsync(refreshToken, cancellationToken);

            // Entra may or may not issue a new refresh token; keep the old one when it does not.
            Store(cacheKey, subject, response with
            {
                RefreshToken = response.RefreshToken ?? refreshToken
            });

            return response.AccessToken;
        }
        catch (TokenExchangeFailedException exception)
        {
            _logger.LogInformation(
                "Refresh token rejected for user {Subject}: {ErrorCode}",
                subject, exception.ErrorCode ?? "(no code)");

            return null;
        }
    }

    private async Task<TokenResponse> PostAsync(
        Dictionary<string, string> form,
        string grantDescription,
        CancellationToken cancellationToken)
    {
        var tokenEndpoint =
            $"https://login.microsoftonline.com/{_options.OboTenantId}/oauth2/v2.0/token";

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form)
        };

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var errorCode = AadstsCode().Match(body) is { Success: true } match ? match.Value : null;

            // The response body is logged because Entra's AADSTS descriptions are the only useful
            // diagnostic here, and it contains no token material on a failure.
            _logger.LogError(
                "Entra {Grant} exchange failed: {Status} {ErrorCode}",
                grantDescription, (int)response.StatusCode, errorCode ?? "(no code)");

            throw new TokenExchangeFailedException(
                DescribeFailure(errorCode, body), errorCode);
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        var accessToken = root.TryGetProperty("access_token", out var accessElement)
            ? accessElement.GetString()
            : null;

        if (string.IsNullOrEmpty(accessToken))
        {
            throw new TokenExchangeFailedException(
                "Entra returned a successful response with no access token.");
        }

        var refreshToken = root.TryGetProperty("refresh_token", out var refreshElement)
            ? refreshElement.GetString()
            : null;

        _logger.LogInformation(
            "Entra {Grant} exchange succeeded (token length {Length}, refresh token {HasRefresh})",
            grantDescription, accessToken.Length, refreshToken is null ? "absent" : "issued");

        return new TokenResponse(accessToken, refreshToken);
    }

    /// <summary>Turns an Entra failure into guidance the caller can act on.</summary>
    private static string DescribeFailure(string? errorCode, string body) => errorCode switch
    {
        // The assertion had already expired when Entra saw it.
        "AADSTS50013" => "The sign-in token has expired. Sign in again.",

        // Consent is missing, or a condition such as MFA has to be satisfied interactively.
        "AADSTS65001" or "AADSTS50076" or "AADSTS50079" =>
            "Additional consent or verification is required before this server can access " +
            "OneDrive on your behalf. Complete the Microsoft sign-in prompt and try again.",

        // The app registration is not permitted to exchange this token.
        "AADSTS50105" or "AADSTS700016" =>
            "This server's Entra application is not authorised to access OneDrive for your " +
            "account. An administrator needs to grant the Files.ReadWrite delegated permission.",

        _ => $"Microsoft Entra rejected the token exchange{(errorCode is null ? string.Empty : $" ({errorCode})")}."
    };

    // ------------------------------------------------------------------ cache

    private void Store(string cacheKey, string? subject, TokenResponse response)
    {
        var entry = new CachedToken(
            response.AccessToken,
            ResolveExpiry(response.AccessToken),
            response.RefreshToken);

        _tokenCache[cacheKey] = entry;

        if (subject is { Length: > 0 })
        {
            _latestKeyByUser[subject] = cacheKey;
        }
    }

    /// <summary>
    /// Derives the cache key from the assertion itself, so an entry can only ever be read back
    /// by a request presenting that same token.
    /// </summary>
    private static string ComputeCacheKey(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>Reads the Graph token's own expiry, falling back to the configured lifetime.</summary>
    private DateTimeOffset ResolveExpiry(string accessToken)
    {
        var fallback = DateTimeOffset.UtcNow.AddMinutes(_options.OboTokenCacheMinutes);

        try
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(accessToken))
            {
                return fallback;
            }

            var expiry = new DateTimeOffset(handler.ReadJwtToken(accessToken).ValidTo, TimeSpan.Zero);

            return expiry <= DateTimeOffset.UtcNow ? fallback : expiry - ExpiryBuffer;
        }
        catch (ArgumentException)
        {
            // Graph tokens are not contractually JWTs; if it cannot be read, time-box it instead.
            return fallback;
        }
    }

    private void RemoveExpired()
    {
        foreach (var (key, entry) in _tokenCache)
        {
            if (entry.IsExpired)
            {
                _tokenCache.TryRemove(key, out _);
            }
        }
    }

    // ------------------------------------------------------------------ validation

    private void EnsureConfigured()
    {
        var missing = new List<string>();

        if (string.IsNullOrWhiteSpace(_options.OboTenantId))
        {
            missing.Add("OneDrive:OboTenantId");
        }

        if (string.IsNullOrWhiteSpace(_options.OboClientId))
        {
            missing.Add("OneDrive:OboClientId");
        }

        if (string.IsNullOrWhiteSpace(_options.OboClientSecret))
        {
            missing.Add("OneDrive:OboClientSecret");
        }

        if (missing.Count > 0)
        {
            throw new TokenExchangeFailedException(
                "This server is not configured to access OneDrive. Missing settings: " +
                string.Join(", ", missing) + ".");
        }
    }

    /// <summary>
    /// Rejects an assertion that has already expired.
    /// </summary>
    /// <remarks>
    /// Checking locally turns an opaque <c>AADSTS50013</c> from Entra into a clear "sign in
    /// again", and saves a pointless round trip.
    /// </remarks>
    private void EnsureAssertionIsUsable(UserCredential credential)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(credential.RawToken))
            {
                return;
            }

            var expiry = handler.ReadJwtToken(credential.RawToken).ValidTo;

            if (expiry == DateTime.MinValue)
            {
                return;
            }

            if (expiry <= DateTime.UtcNow)
            {
                throw new AuthenticationRequiredException(
                    "The sign-in token expired at " +
                    expiry.ToString("u", CultureInfo.InvariantCulture) +
                    ". Sign in again.");
            }

            var remaining = expiry - DateTime.UtcNow;

            if (remaining < TimeSpan.FromSeconds(30))
            {
                _logger.LogWarning(
                    "Caller token expires in {Seconds}s; the exchange may fail",
                    (int)remaining.TotalSeconds);
            }
        }
        catch (ArgumentException)
        {
            // Not readable as a JWT. Let Entra be the authority on whether it is acceptable.
        }
    }

    private string ResolveScope()
    {
        var scope = _options.OboGraphScope;

        // Without offline_access no refresh token is issued and the rotation path silently
        // degrades into a full exchange on every call.
        return scope.Contains("offline_access", StringComparison.OrdinalIgnoreCase)
            ? scope
            : $"{scope} offline_access";
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _cleanupTimer.Dispose();
        _tokenCache.Clear();
        _latestKeyByUser.Clear();
        _disposed = true;
    }

    private sealed record TokenResponse(string AccessToken, string? RefreshToken);

    private sealed record CachedToken(
        string AccessToken,
        DateTimeOffset ExpiresAt,
        string? RefreshToken)
    {
        public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
    }
}
