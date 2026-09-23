using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using OneDriveMcp.Server.Tests.Fixtures;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// The authorization server endpoints.
/// </summary>
/// <remarks>
/// This server issues its own tokens because Entra ID does not support Dynamic Client
/// Registration, so an MCP client cannot otherwise obtain credentials without someone creating an
/// app registration by hand. These tests cover the parts a client actually depends on, and the
/// refusals that keep the flow safe.
/// </remarks>
[Collection(OAuthServerCollection.Name)]
public class OAuthEndpointTests(OAuthServerFixture server)
{
    private readonly OAuthServerFixture _server = server;

    // ---------------------------------------------------------------- discovery

    [Fact]
    public async Task AuthorizationServerMetadata_DescribesEveryEndpoint()
    {
        using var client = _server.CreateClient();

        var metadata = await client.GetFromJsonAsync<JsonElement>(
            "/.well-known/oauth-authorization-server");

        Assert.Equal(OAuthServerFixture.Issuer, metadata.GetProperty("issuer").GetString());
        Assert.EndsWith("/oauth/authorize", metadata.GetProperty("authorization_endpoint").GetString()!, StringComparison.Ordinal);
        Assert.EndsWith("/oauth/token", metadata.GetProperty("token_endpoint").GetString()!, StringComparison.Ordinal);
        Assert.EndsWith("/oauth/register", metadata.GetProperty("registration_endpoint").GetString()!, StringComparison.Ordinal);
        Assert.EndsWith("/oauth/revoke", metadata.GetProperty("revocation_endpoint").GetString()!, StringComparison.Ordinal);
        Assert.EndsWith("/oauth/jwks", metadata.GetProperty("jwks_uri").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthorizationServerMetadata_AdvertisesS256Only()
    {
        // Plain PKCE offers no protection against an attacker who can observe the authorization
        // request, which is the threat PKCE exists to address. Advertising it would invite use.
        using var client = _server.CreateClient();

        var metadata = await client.GetFromJsonAsync<JsonElement>(
            "/.well-known/oauth-authorization-server");

        var methods = metadata.GetProperty("code_challenge_methods_supported")
            .EnumerateArray().Select(m => m.GetString()).ToList();

        Assert.Equal(["S256"], methods);
    }

    [Fact]
    public async Task Jwks_PublishesTheSigningKey()
    {
        using var client = _server.CreateClient();

        var jwks = await client.GetFromJsonAsync<JsonElement>("/oauth/jwks");
        var keys = jwks.GetProperty("keys");

        Assert.True(keys.GetArrayLength() >= 1);

        var key = keys[0];

        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("kid").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("n").GetString()));
    }

    [Fact]
    public async Task Jwks_NeverExposesPrivateKeyMaterial()
    {
        using var client = _server.CreateClient();

        var body = await client.GetStringAsync("/oauth/jwks");

        // "d" is the RSA private exponent. Its presence would make the document a private key.
        foreach (var privateComponent in new[] { "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"" })
        {
            Assert.DoesNotContain(privateComponent, body, StringComparison.Ordinal);
        }
    }

    // ---------------------------------------------------------------- registration

    [Fact]
    public async Task Registration_IssuesAClientId()
    {
        using var client = _server.CreateClient();

        var response = await RegisterAsync(client, new
        {
            client_name = "Test Client",
            redirect_uris = new[] { "https://client.test/callback" }
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("client_id").GetString()));
    }

    [Fact]
    public async Task Registration_ResponseIsNotCacheable()
    {
        using var client = _server.CreateClient();

        var response = await RegisterAsync(client, new
        {
            redirect_uris = new[] { "https://client.test/callback" }
        });

        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Registration_ReturnsASecretOnlyForAConfidentialClient()
    {
        using var client = _server.CreateClient();

        var publicClient = await (await RegisterAsync(client, new
        {
            redirect_uris = new[] { "https://client.test/callback" },
            token_endpoint_auth_method = "none"
        })).Content.ReadFromJsonAsync<JsonElement>();

        var confidential = await (await RegisterAsync(client, new
        {
            redirect_uris = new[] { "https://client.test/callback" },
            token_endpoint_auth_method = "client_secret_post"
        })).Content.ReadFromJsonAsync<JsonElement>();

        Assert.True(publicClient.GetProperty("client_secret").ValueKind == JsonValueKind.Null);
        Assert.False(string.IsNullOrWhiteSpace(confidential.GetProperty("client_secret").GetString()));
    }

    [Theory]
    [InlineData("http://client.test/callback")]                 // plaintext, not loopback
    [InlineData("not-an-absolute-uri")]
    [InlineData("https://client.test/callback#fragment")]
    public async Task Registration_RejectsUnsafeRedirectUris(string redirectUri)
    {
        using var client = _server.CreateClient();

        var response = await RegisterAsync(client, new { redirect_uris = new[] { redirectUri } });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("http://localhost:1234/callback")]
    [InlineData("http://127.0.0.1:5173/callback")]
    public async Task Registration_AllowsPlaintextLoopbackRedirects(string redirectUri)
    {
        // A local client cannot obtain a certificate, and there is no network to intercept.
        using var client = _server.CreateClient();

        var response = await RegisterAsync(client, new { redirect_uris = new[] { redirectUri } });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Registration_RequiresAtLeastOneRedirectUri()
    {
        using var client = _server.CreateClient();

        var response = await RegisterAsync(client, new { client_name = "No redirects" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---------------------------------------------------------------- authorize

    [Fact]
    public async Task Authorize_RejectsAnUnknownClient()
    {
        using var client = _server.CreateNonRedirectingClient();

        var response = await client.GetAsync(
            "/oauth/authorize?response_type=code&client_id=nope&redirect_uri=https://x.test/cb" +
            "&code_challenge=abc&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Authorize_RejectsARedirectUriThatWasNotRegistered()
    {
        // Without this an attacker who learns a client id could have the code delivered to an
        // address of their own choosing.
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateNonRedirectingClient();

        var response = await client.GetAsync(
            $"/oauth/authorize?response_type=code&client_id={clientId}" +
            "&redirect_uri=https://attacker.test/callback" +
            "&code_challenge=abc&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Authorize_RequiresPkce()
    {
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateNonRedirectingClient();

        var response = await client.GetAsync(
            $"/oauth/authorize?response_type=code&client_id={clientId}" +
            "&redirect_uri=https://client.test/callback");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Authorize_RejectsPlainPkce()
    {
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateNonRedirectingClient();

        var response = await client.GetAsync(
            $"/oauth/authorize?response_type=code&client_id={clientId}" +
            "&redirect_uri=https://client.test/callback" +
            "&code_challenge=abc&code_challenge_method=plain");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Authorize_RejectsAnImplicitFlowRequest()
    {
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateNonRedirectingClient();

        var response = await client.GetAsync(
            $"/oauth/authorize?response_type=token&client_id={clientId}" +
            "&redirect_uri=https://client.test/callback" +
            "&code_challenge=abc&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Authorize_AcceptsAWellFormedRequest()
    {
        // Establishes that a valid request gets past validation, which is the part these tests
        // own. What happens next is an Entra sign-in, and this fixture's tenant is fictitious, so
        // the redirect itself cannot be exercised here -- the handler fails fetching discovery
        // metadata for a tenant that does not exist. Asserting "not rejected as invalid" is the
        // honest boundary; the interactive flow needs a real tenant and is an end-to-end check.
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateNonRedirectingClient();

        var response = await client.GetAsync(
            $"/oauth/authorize?response_type=code&client_id={clientId}" +
            "&redirect_uri=https://client.test/callback" +
            "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");

        Assert.NotEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---------------------------------------------------------------- token

    [Fact]
    public async Task Token_RejectsAnUnsupportedGrantType()
    {
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateClient();

        var response = await client.PostAsync("/oauth/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "password"),
            new KeyValuePair<string, string>("client_id", clientId)
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal("unsupported_grant_type", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_RejectsAnUnknownClient()
    {
        using var client = _server.CreateClient();

        var response = await client.PostAsync("/oauth/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("client_id", "does-not-exist"),
            new KeyValuePair<string, string>("code", "x"),
            new KeyValuePair<string, string>("redirect_uri", "https://client.test/callback"),
            new KeyValuePair<string, string>("code_verifier", "y")
        ]));

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_RejectsAnUnknownAuthorizationCode()
    {
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateClient();

        var response = await client.PostAsync("/oauth/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("code", "never-issued"),
            new KeyValuePair<string, string>("redirect_uri", "https://client.test/callback"),
            new KeyValuePair<string, string>("code_verifier", "whatever")
        ]));

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_ResponseIsNotCacheable()
    {
        var clientId = await RegisterClientAsync("https://client.test/callback");

        using var client = _server.CreateClient();

        var response = await client.PostAsync("/oauth/token", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("refresh_token", "nope")
        ]));

        // The body of a successful response is a credential, so it must never be stored.
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    // ---------------------------------------------------------------- revocation

    [Fact]
    public async Task Revocation_AlwaysReportsSuccess()
    {
        // RFC 7009 requires 200 regardless, so a caller cannot probe which tokens exist.
        using var client = _server.CreateClient();

        var response = await client.PostAsync("/oauth/revoke", new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("token", "not-a-real-token")
        ]));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---------------------------------------------------------------- helpers

    private static Task<HttpResponseMessage> RegisterAsync(HttpClient client, object request) =>
        client.PostAsJsonAsync("/oauth/register", request);

    private async Task<string> RegisterClientAsync(string redirectUri)
    {
        using var client = _server.CreateClient();

        var response = await RegisterAsync(client, new { redirect_uris = new[] { redirectUri } });
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        return body.GetProperty("client_id").GetString()!;
    }
}
