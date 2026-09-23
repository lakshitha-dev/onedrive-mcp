using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Tests.Fakes;

namespace OneDriveMcp.Core.Tests.Auth;

public class OboGraphTokenServiceTests
{
    // ---------------------------------------------------------------- refusals

    [Fact]
    public async Task NoCredential_RequiresAuthentication()
    {
        using var harness = new OboHarness(credential: null);

        await Assert.ThrowsAsync<AuthenticationRequiredException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Empty(harness.Handler.Requests);
    }

    [Fact]
    public async Task SelfIssuedToken_WithNoStoredAccess_AsksTheUserToSignIn()
    {
        // Entra rejects a self-signed JWT as an on-behalf-of assertion, so it is never sent as
        // one. With nothing stored for this user there is nothing to redeem either, and the only
        // fix is an interactive sign-in -- so the message says exactly that.
        using var harness = new OboHarness(TestCredential.SelfIssued("user-one"));

        var exception = await Assert.ThrowsAsync<AuthenticationRequiredException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Contains("Sign in again", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(harness.Handler.Requests);
    }

    [Fact]
    public async Task MissingConfiguration_NamesTheSettingsThatAreAbsent()
    {
        using var harness = new OboHarness(
            TestCredential.Entra(),
            configure: options =>
            {
                options.OboTenantId = null;
                options.OboClientId = null;
                options.OboClientSecret = null;
            });

        var exception = await Assert.ThrowsAsync<TokenExchangeFailedException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Contains("OneDrive:OboTenantId", exception.Message, StringComparison.Ordinal);
        Assert.Contains("OneDrive:OboClientId", exception.Message, StringComparison.Ordinal);
        Assert.Contains("OneDrive:OboClientSecret", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Handler.Requests);
    }

    [Fact]
    public async Task ExpiredAssertion_IsRejectedWithoutCallingEntra()
    {
        // Checking locally turns an opaque AADSTS50013 into a clear "sign in again".
        using var harness = new OboHarness(
            TestCredential.Entra(expiresIn: TimeSpan.FromMinutes(-5)));

        var exception = await Assert.ThrowsAsync<AuthenticationRequiredException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Contains("expired", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(harness.Handler.Requests);
    }

    // ---------------------------------------------------------------- exchange

    [Fact]
    public async Task EntraToken_IsExchangedByTheOnBehalfOfGrant()
    {
        var expected = GraphToken("graph-token-1");

        using var harness = new OboHarness(TestCredential.Entra());
        harness.Handler.EnqueueJson(TokenJson(expected, "refresh-1"));

        var token = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(expected, token);

        var form = ParseForm(harness.Handler.SingleRequest.Body);

        Assert.Equal("urn:ietf:params:oauth:grant-type:jwt-bearer", form["grant_type"]);
        Assert.Equal("on_behalf_of", form["requested_token_use"]);
        Assert.Equal(TestCredential.EntraRawToken, form["assertion"]);
        Assert.Equal("test-client", form["client_id"]);
    }

    [Fact]
    public async Task ExchangeTargetsTheConfiguredTenant()
    {
        using var harness = new OboHarness(TestCredential.Entra());
        harness.Handler.EnqueueJson(TokenJson(GraphToken("graph-token-1")));

        await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(
            "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
            harness.Handler.SingleRequest.Url);
    }

    [Fact]
    public async Task OfflineAccessIsAppendedWhenTheConfiguredScopeOmitsIt()
    {
        // Without offline_access Entra issues no refresh token, and the rotation path silently
        // degrades into a full exchange on every single call.
        using var harness = new OboHarness(
            TestCredential.Entra(),
            configure: options => options.OboGraphScope = "https://graph.microsoft.com/Files.ReadWrite");

        harness.Handler.EnqueueJson(TokenJson(GraphToken("graph-token-1")));

        await harness.Service.GetGraphTokenAsync(default);

        var scope = ParseForm(harness.Handler.SingleRequest.Body)["scope"];

        Assert.Contains("offline_access", scope, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OfflineAccessIsNotDuplicated()
    {
        using var harness = new OboHarness(
            TestCredential.Entra(),
            configure: options => options.OboGraphScope = "Files.ReadWrite offline_access");

        harness.Handler.EnqueueJson(TokenJson(GraphToken("graph-token-1")));

        await harness.Service.GetGraphTokenAsync(default);

        var scope = ParseForm(harness.Handler.SingleRequest.Body)["scope"];

        Assert.Equal("Files.ReadWrite offline_access", scope);
    }

    // ---------------------------------------------------------------- caching

    [Fact]
    public async Task RepeatedCallsWithTheSameTokenHitTheCache()
    {
        using var harness = new OboHarness(TestCredential.Entra());
        harness.Handler.EnqueueJson(
            TokenJson(GraphToken("graph-token-1"), expiresIn: TimeSpan.FromMinutes(30)));

        var first = await harness.Service.GetGraphTokenAsync(default);
        var second = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(first, second);
        Assert.Single(harness.Handler.Requests);
    }

    [Fact]
    public async Task DifferentUsersNeverShareACachedToken()
    {
        // The cache key is a hash of the assertion, so an entry can only be read back by a
        // request presenting that same token. A collision here would be a cross-user data leak.
        var accessor = new MutableCredentialAccessor(TestCredential.Entra(oid: "user-one"));

        var tokenOne = GraphToken("graph-token-user-one");
        var tokenTwo = GraphToken("graph-token-user-two");

        using var harness = new OboHarness(accessor);
        harness.Handler
            .EnqueueJson(TokenJson(tokenOne, expiresIn: TimeSpan.FromMinutes(30)))
            .EnqueueJson(TokenJson(tokenTwo, expiresIn: TimeSpan.FromMinutes(30)));

        var first = await harness.Service.GetGraphTokenAsync(default);

        accessor.Current = TestCredential.Entra(oid: "user-two");
        var second = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(tokenOne, first);
        Assert.Equal(tokenTwo, second);
        Assert.NotEqual(first, second);
        Assert.Equal(2, harness.Handler.Requests.Count);
    }

    [Fact]
    public async Task ARotatedCallerTokenIsServedByRedeemingTheRefreshToken()
    {
        // Same user, new caller token. Redeeming the stored refresh token avoids a second full
        // on-behalf-of exchange, which is the point of tracking the latest key per user.
        var accessor = new MutableCredentialAccessor(
            TestCredential.Entra(oid: "user-one", nonce: "first"));

        var rotated = GraphToken("graph-token-2", TimeSpan.FromMinutes(30));

        using var harness = new OboHarness(accessor);
        harness.Handler
            .EnqueueJson(TokenJson(GraphToken("graph-token-1"), "refresh-1", TimeSpan.FromMinutes(30)))
            .EnqueueJson(TokenJson(rotated, "refresh-2", TimeSpan.FromMinutes(30)));

        await harness.Service.GetGraphTokenAsync(default);

        accessor.Current = TestCredential.Entra(oid: "user-one", nonce: "second");
        var second = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(rotated, second);

        var form = ParseForm(harness.Handler.Requests[1].Body);

        Assert.Equal("refresh_token", form["grant_type"]);
        Assert.Equal("refresh-1", form["refresh_token"]);
    }

    [Fact]
    public async Task AFailedRefreshFallsBackToAFullExchange()
    {
        var accessor = new MutableCredentialAccessor(
            TestCredential.Entra(oid: "user-one", nonce: "first"));

        var recovered = GraphToken("graph-token-3", TimeSpan.FromMinutes(30));

        using var harness = new OboHarness(accessor);
        harness.Handler
            .EnqueueJson(TokenJson(GraphToken("graph-token-1"), "refresh-1", TimeSpan.FromMinutes(30)))
            .EnqueueJson(
                """{"error":"invalid_grant","error_description":"AADSTS700082 expired"}""",
                HttpStatusCode.BadRequest)
            .EnqueueJson(TokenJson(recovered, "refresh-3", TimeSpan.FromMinutes(30)));

        await harness.Service.GetGraphTokenAsync(default);

        accessor.Current = TestCredential.Entra(oid: "user-one", nonce: "second");
        var result = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(recovered, result);
        Assert.Equal(3, harness.Handler.Requests.Count);
        Assert.Equal(
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ParseForm(harness.Handler.Requests[2].Body)["grant_type"]);
    }

    // ---------------------------------------------------------------- the DCR bridge

    [Fact]
    public async Task SelfIssuedToken_RedeemsTheStoredDelegatedAccess()
    {
        // This is the whole point of the bridge. A client that registered through Dynamic Client
        // Registration holds a token this server signed, which Entra will not accept as an
        // assertion. Without this path every Graph call from such a client fails.
        var expected = GraphToken("graph-for-dcr-client");

        using var harness = new OboHarness(TestCredential.SelfIssued("user-one"));
        harness.EntraRefreshTokens.Seed("user-one", "stored-refresh-1");
        harness.Handler.EnqueueJson(TokenJson(expected, "stored-refresh-2"));

        var token = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(expected, token);

        var form = ParseForm(harness.Handler.SingleRequest.Body);

        Assert.Equal("refresh_token", form["grant_type"]);
        Assert.Equal("stored-refresh-1", form["refresh_token"]);
    }

    [Fact]
    public async Task SelfIssuedToken_StoresTheRotatedRefreshToken()
    {
        // Entra rotates the refresh token on use. Keeping the old one would work exactly once.
        using var harness = new OboHarness(TestCredential.SelfIssued("user-one"));
        harness.EntraRefreshTokens.Seed("user-one", "stored-refresh-1");
        harness.Handler.EnqueueJson(TokenJson(GraphToken("graph-1"), "stored-refresh-2"));

        await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal("stored-refresh-2", harness.EntraRefreshTokens.Current("user-one"));
        Assert.Contains(("user-one", "stored-refresh-2"), harness.EntraRefreshTokens.Writes);
    }

    [Fact]
    public async Task SelfIssuedToken_CachesSoEachCallIsNotAnExchange()
    {
        using var harness = new OboHarness(TestCredential.SelfIssued("user-one"));
        harness.EntraRefreshTokens.Seed("user-one", "stored-refresh-1");
        harness.Handler.EnqueueJson(
            TokenJson(GraphToken("graph-1"), "stored-refresh-2", TimeSpan.FromMinutes(30)));

        var first = await harness.Service.GetGraphTokenAsync(default);
        var second = await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(first, second);
        Assert.Single(harness.Handler.Requests);
    }

    [Fact]
    public async Task SelfIssuedToken_DiscardsStoredAccessThatEntraRejects()
    {
        // A stored token that no longer works can never start working again, so keeping it would
        // mean every future request pays for a doomed round trip before failing the same way.
        using var harness = new OboHarness(TestCredential.SelfIssued("user-one"));
        harness.EntraRefreshTokens.Seed("user-one", "expired-refresh");
        harness.Handler.EnqueueJson(
            """{"error":"invalid_grant","error_description":"AADSTS700082 token expired"}""",
            HttpStatusCode.BadRequest);

        var exception = await Assert.ThrowsAsync<AuthenticationRequiredException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Contains("Sign in again", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("user-one", harness.EntraRefreshTokens.Removals);
        Assert.Null(harness.EntraRefreshTokens.Current("user-one"));
    }

    [Fact]
    public async Task SelfIssuedToken_NeverRedeemsAnotherUsersAccess()
    {
        // The lookup is keyed on the token's subject. If that ever stopped matching the identity
        // the access was stored under, one user would be served another user's drive.
        using var harness = new OboHarness(TestCredential.SelfIssued("user-two"));
        harness.EntraRefreshTokens.Seed("user-one", "user-one-refresh");

        await Assert.ThrowsAsync<AuthenticationRequiredException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Empty(harness.Handler.Requests);
        Assert.Equal("user-one-refresh", harness.EntraRefreshTokens.Current("user-one"));
    }

    [Fact]
    public async Task SelfIssuedToken_WithoutASubjectIsRefused()
    {
        var credential = new UserCredential(
            TestCredential.Jwt(new Dictionary<string, object> { ["iss"] = "https://onedrive-mcp.test" }),
            Subject: null,
            "https://onedrive-mcp.test",
            IsEntra: false);

        using var harness = new OboHarness(credential);

        var exception = await Assert.ThrowsAsync<AuthenticationRequiredException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Contains("no subject", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EntraToken_StillUsesOnBehalfOfRatherThanTheStore()
    {
        // A genuine Entra token is exchanged directly. Routing it through the store would be
        // slower and would fail for any user who had never been through the consent page.
        using var harness = new OboHarness(TestCredential.Entra("user-one"));
        harness.EntraRefreshTokens.Seed("user-one", "stored-refresh-1");
        harness.Handler.EnqueueJson(TokenJson(GraphToken("graph-1")));

        await harness.Service.GetGraphTokenAsync(default);

        Assert.Equal(
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ParseForm(harness.Handler.SingleRequest.Body)["grant_type"]);
    }

    // ---------------------------------------------------------------- failures

    [Theory]
    [InlineData("AADSTS50013", "expired")]
    [InlineData("AADSTS65001", "consent")]
    [InlineData("AADSTS50105", "administrator")]
    public async Task EntraErrorCodesBecomeActionableGuidance(string aadsts, string expectedWord)
    {
        using var harness = new OboHarness(TestCredential.Entra());
        harness.Handler.EnqueueJson(
            $"{{\"error\":\"invalid_grant\",\"error_description\":\"{aadsts}: something\"}}",
            HttpStatusCode.BadRequest);

        var exception = await Assert.ThrowsAsync<TokenExchangeFailedException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Equal(aadsts, exception.ErrorCode);
        Assert.Contains(expectedWord, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnUnrecognisedFailureStillReportsTheCode()
    {
        using var harness = new OboHarness(TestCredential.Entra());
        harness.Handler.EnqueueJson(
            """{"error":"invalid_request","error_description":"AADSTS900144 missing parameter"}""",
            HttpStatusCode.BadRequest);

        var exception = await Assert.ThrowsAsync<TokenExchangeFailedException>(
            () => harness.Service.GetGraphTokenAsync(default));

        Assert.Equal("AADSTS900144", exception.ErrorCode);
        Assert.Contains("AADSTS900144", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASuccessWithNoAccessTokenIsTreatedAsAFailure()
    {
        using var harness = new OboHarness(TestCredential.Entra());
        harness.Handler.EnqueueJson("""{"token_type":"Bearer","expires_in":3600}""");

        await Assert.ThrowsAsync<TokenExchangeFailedException>(
            () => harness.Service.GetGraphTokenAsync(default));
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>
    /// Builds a Graph access token. It has to be a readable JWT so the service can take the
    /// expiry from it; the marker makes the value identifiable in an assertion.
    /// </summary>
    private static string GraphToken(string marker, TimeSpan? expiresIn = null) =>
        TestCredential.Jwt(
            new Dictionary<string, object>
            {
                ["sub"] = marker,
                ["aud"] = "https://graph.microsoft.com",
                ["exp"] = DateTimeOffset.UtcNow.Add(expiresIn ?? TimeSpan.FromHours(1)).ToUnixTimeSeconds()
            },
            marker: marker);

    /// <summary>Builds an Entra token-endpoint response around an already-built access token.</summary>
    private static string TokenJson(
        string accessToken,
        string? refreshToken = null,
        TimeSpan? expiresIn = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["token_type"] = "Bearer",
            ["expires_in"] = (int)(expiresIn ?? TimeSpan.FromHours(1)).TotalSeconds,
            ["access_token"] = accessToken
        };

        if (refreshToken is not null)
        {
            payload["refresh_token"] = refreshToken;
        }

        return JsonSerializer.Serialize(payload);
    }

    private static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(
                parts => Uri.UnescapeDataString(parts[0]),
                parts => parts.Length > 1 ? Uri.UnescapeDataString(parts[1].Replace('+', ' ')) : string.Empty,
                StringComparer.Ordinal);

    /// <summary>Builds the service over a stub token endpoint.</summary>
    private sealed class OboHarness : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly OboGraphTokenService _service;

        public OboHarness(UserCredential? credential, Action<OneDriveOptions>? configure = null)
            : this(new MutableCredentialAccessor(credential), configure)
        {
        }

        public OboHarness(IUserCredentialAccessor accessor, Action<OneDriveOptions>? configure = null)
        {
            var options = new OneDriveOptions
            {
                OboTenantId = "test-tenant",
                OboClientId = "test-client",
                OboClientSecret = "test-secret"
            };

            configure?.Invoke(options);

            _httpClient = new HttpClient(Handler);

            _service = new OboGraphTokenService(
                _httpClient,
                accessor,
                EntraRefreshTokens,
                Options.Create(options),
                NullLogger<OboGraphTokenService>.Instance);
        }

        public StubHttpMessageHandler Handler { get; } = new();

        /// <summary>The delegated access this server holds, keyed by user.</summary>
        public FakeEntraRefreshTokenStore EntraRefreshTokens { get; } = new();

        public IGraphTokenService Service => _service;

        public void Dispose()
        {
            _service.Dispose();
            _httpClient.Dispose();
        }
    }

    private sealed class MutableCredentialAccessor(UserCredential? credential) : IUserCredentialAccessor
    {
        public UserCredential? Current { get; set; } = credential;
    }
}

/// <summary>Builds credentials for the token-exchange tests.</summary>
internal static class TestCredential
{
    /// <summary>The raw token returned by <see cref="Entra"/> with default arguments.</summary>
    public static string EntraRawToken { get; } = BuildEntraToken("user-one", null, TimeSpan.FromHours(1));

    public static UserCredential Entra(
        string oid = "user-one",
        string? nonce = null,
        TimeSpan? expiresIn = null)
    {
        var raw = BuildEntraToken(oid, nonce, expiresIn ?? TimeSpan.FromHours(1));

        return new UserCredential(
            raw,
            oid,
            "https://login.microsoftonline.com/test-tenant/v2.0",
            IsEntra: true);
    }

    public static UserCredential SelfIssued(string subject = "dcr-client") =>
        new(
            Jwt(new Dictionary<string, object> { ["sub"] = subject }),
            subject,
            "https://onedrive-mcp.test",
            IsEntra: false);

    private static string BuildEntraToken(string oid, string? nonce, TimeSpan expiresIn)
    {
        var claims = new Dictionary<string, object>
        {
            ["oid"] = oid,
            ["iss"] = "https://login.microsoftonline.com/test-tenant/v2.0",
            ["exp"] = DateTimeOffset.UtcNow.Add(expiresIn).ToUnixTimeSeconds()
        };

        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }

        return Jwt(claims);
    }

    /// <summary>Builds an unsigned JWT; signature validation is not exercised here.</summary>
    public static string Jwt(Dictionary<string, object> payload, string? marker = null)
    {
        static string Segment(object value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Segment(new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT" });

        return $"{header}.{Segment(payload)}.{marker ?? "signature"}";
    }
}
