using System.Net;
using System.Text.Json;
using OneDriveMcp.Server.Tests.Fixtures;

namespace OneDriveMcp.Server.Tests;

[Collection(McpServerCollection.Name)]
public class McpEndpointTests(McpServerFixture server)
{
    private readonly McpServerFixture _factory = server;

    [Fact]
    public async Task Health_IsAnonymousAndHealthy()
    {
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ListTools_ExposesToolsFromTheCoreAssembly()
    {
        // Guards against the WithToolsFromAssembly() trap: that overload defaults to the calling
        // assembly (the host), where no tool types live, and would silently register none.
        var mcp = new McpTestClient(_factory.CreateClient());

        var response = await mcp.ListToolsAsync();

        var tools = response.GetProperty("result").GetProperty("tools");
        var names = tools.EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToList();

        Assert.NotEmpty(names);
        Assert.Contains("onedrive_auth_status", names);
    }

    [Fact]
    public async Task ListTools_PublishesAnnotationsAndSchemas()
    {
        var mcp = new McpTestClient(_factory.CreateClient());

        var response = await mcp.ListToolsAsync();

        var tool = response.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == "onedrive_auth_status");

        Assert.True(tool.GetProperty("annotations").GetProperty("readOnlyHint").GetBoolean());
        Assert.True(tool.TryGetProperty("inputSchema", out _));

        // UseStructuredContent on the attribute is what produces the output schema; without it
        // clients only receive an unstructured text blob.
        Assert.True(tool.TryGetProperty("outputSchema", out _));
    }

    [Fact]
    public async Task CallTool_WithoutToken_ReportsUnauthenticated()
    {
        var mcp = new McpTestClient(_factory.CreateClient());

        var result = await CallAuthStatusAsync(mcp, bearerToken: null);

        Assert.False(result.GetProperty("authenticated").GetBoolean());
        Assert.Equal("none", result.GetProperty("tokenKind").GetString());
    }

    /// <summary>
    /// The load-bearing test for the whole token design.
    /// </summary>
    /// <remarks>
    /// Every tool call is an independent HTTP request, so the credential must be read from the
    /// request in flight rather than captured once per session. If someone reintroduces a
    /// session-scoped or AsyncLocal cache -- or sets PerSessionExecutionContext, which stops
    /// IHttpContextAccessor resolving inside handlers -- the second and third calls here would
    /// return the first caller's identity. That would be a cross-user data leak, not a bug.
    /// </remarks>
    [Fact]
    public async Task CallTool_ResolvesCredentialPerRequest_NotPerSession()
    {
        using var client = _factory.CreateClient();
        var mcp = new McpTestClient(client);

        var first = await CallAuthStatusAsync(mcp, TestTokens.Entra("user-one"));
        var second = await CallAuthStatusAsync(mcp, TestTokens.Entra("user-two"));
        var third = await CallAuthStatusAsync(mcp, bearerToken: null);
        var fourth = await CallAuthStatusAsync(mcp, TestTokens.Entra("user-one"));

        Assert.Equal("user-one", first.GetProperty("subject").GetString());
        Assert.Equal("user-two", second.GetProperty("subject").GetString());
        Assert.False(third.GetProperty("authenticated").GetBoolean());
        Assert.Equal("user-one", fourth.GetProperty("subject").GetString());
    }

    [Fact]
    public async Task CallTool_DistinguishesEntraFromSelfIssuedTokens()
    {
        // This split drives token exchange: an Entra token goes through on-behalf-of, while a
        // token this server issued via DCR is self-signed, is rejected by Entra as an assertion,
        // and must instead be resolved through the stored Entra refresh token.
        var mcp = new McpTestClient(_factory.CreateClient());

        var entra = await CallAuthStatusAsync(mcp, TestTokens.Entra("user-one"));
        var selfIssued = await CallAuthStatusAsync(mcp, TestTokens.SelfIssued("dcr-client"));

        Assert.Equal("entra", entra.GetProperty("tokenKind").GetString());
        Assert.True(entra.GetProperty("canCallGraphDirectly").GetBoolean());

        Assert.Equal("self-issued", selfIssued.GetProperty("tokenKind").GetString());
        Assert.False(selfIssued.GetProperty("canCallGraphDirectly").GetBoolean());
    }

    private static async Task<JsonElement> CallAuthStatusAsync(McpTestClient mcp, string? bearerToken)
    {
        var response = await mcp.CallToolAsync("onedrive_auth_status", bearerToken: bearerToken);
        return response.GetProperty("result").GetProperty("structuredContent");
    }
}
