using System.Net;
using System.Net.Http.Headers;
using System.Text;
using OneDriveMcp.Server.Tests.Fixtures;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// What an unauthenticated caller gets from the MCP endpoint.
/// </summary>
/// <remarks>
/// The gateway this was extracted from mapped its MCP endpoint with no authorization at all and
/// relied on a custom middleware instead, so removing that middleware would have silently opened
/// the endpoint. These tests make that class of regression fail loudly.
/// </remarks>
[Collection(AuthEnabledServerCollection.Name)]
public class AuthenticationTests(AuthEnabledServerFixture server)
{
    private readonly AuthEnabledServerFixture _server = server;

    [Fact]
    public async Task McpEndpoint_RejectsAnAnonymousCaller()
    {
        using var client = _server.CreateClient();

        var response = await PostMcpAsync(client, bearerToken: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task McpEndpoint_ChallengeAdvertisesWhereToAuthenticate()
    {
        // A bare 401 leaves a spec-compliant client with nowhere to go. The resource_metadata
        // pointer is what lets it discover the authorization server on its own.
        using var client = _server.CreateClient();

        var response = await PostMcpAsync(client, bearerToken: null);
        var challenge = response.Headers.WwwAuthenticate.ToString();

        Assert.Contains("Bearer", challenge, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("resource_metadata", challenge, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task McpEndpoint_RejectsAGarbageToken()
    {
        using var client = _server.CreateClient();

        var response = await PostMcpAsync(client, "not-a-real-token");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedResourceMetadata_IsPublished()
    {
        using var client = _server.CreateClient();

        var response = await client.GetAsync("/.well-known/oauth-protected-resource");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("authorization_servers", body, StringComparison.Ordinal);
        Assert.Contains("login.microsoftonline.com", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HealthChecks_StayAnonymous()
    {
        // A liveness probe cannot carry a bearer token.
        using var client = _server.CreateClient();

        foreach (var path in new[] { "/health", "/health/live", "/health/ready" })
        {
            var response = await client.GetAsync(path);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Theory]
    [InlineData("Content-Security-Policy")]
    [InlineData("X-Content-Type-Options")]
    [InlineData("X-Frame-Options")]
    [InlineData("Referrer-Policy")]
    public async Task SecurityHeadersAreApplied(string header)
    {
        using var client = _server.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.True(
            response.Headers.Contains(header) || response.Content.Headers.Contains(header),
            $"{header} was not present on the response.");
    }

    [Fact]
    public async Task FingerprintingHeadersAreRemoved()
    {
        // Kestrel's own Server header cannot be covered here: it is written by Kestrel after the
        // pipeline runs, and TestServer never adds it at all, so asserting its absence would pass
        // whether or not the suppression worked. It is switched off at the Kestrel level in
        // Program.cs instead, and was caught by inspecting a response from the real server.
        using var client = _server.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.False(response.Headers.Contains("X-Powered-By"));
        Assert.False(response.Headers.Contains("X-AspNet-Version"));
    }

    private static async Task<HttpResponseMessage> PostMcpAsync(HttpClient client, string? bearerToken)
    {
        const string Body = """
            {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
              "io.modelcontextprotocol/protocolVersion":"2026-07-28",
              "io.modelcontextprotocol/clientCapabilities":{}}}}
            """;

        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(Body, Encoding.UTF8, "application/json")
        };

        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Accept.ParseAdd("text/event-stream");
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", "2026-07-28");
        request.Headers.TryAddWithoutValidation("Mcp-Method", "tools/list");

        if (bearerToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }

        return await client.SendAsync(request);
    }
}
