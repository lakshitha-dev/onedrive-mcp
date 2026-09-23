using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace OneDriveMcp.Server.Tests.Fixtures;

/// <summary>
/// Minimal JSON-RPC client for the Streamable HTTP endpoint.
/// </summary>
/// <remarks>
/// The 2026-07-28 protocol revision has no <c>initialize</c> handshake and no session id, so a
/// call is a single self-describing POST. It does require the <c>MCP-Protocol-Version</c>,
/// <c>Mcp-Method</c> and (for tool calls) <c>Mcp-Name</c> headers, plus the protocol version and
/// client capabilities in <c>params._meta</c>. Responses come back as a one-event SSE stream.
/// </remarks>
internal sealed class McpTestClient(HttpClient httpClient)
{
    private const string ProtocolVersion = "2026-07-28";

    public Task<JsonElement> ListToolsAsync(string? bearerToken = null) =>
        SendAsync("tools/list", mcpName: null, parameters: null, bearerToken);

    public Task<JsonElement> CallToolAsync(
        string toolName,
        object? arguments = null,
        string? bearerToken = null)
    {
        var parameters = new Dictionary<string, object?>
        {
            ["name"] = toolName,
            ["arguments"] = arguments ?? new Dictionary<string, object?>()
        };

        return SendAsync("tools/call", toolName, parameters, bearerToken);
    }

    private async Task<JsonElement> SendAsync(
        string method,
        string? mcpName,
        Dictionary<string, object?>? parameters,
        string? bearerToken)
    {
        parameters ??= [];
        parameters["_meta"] = new Dictionary<string, object?>
        {
            ["io.modelcontextprotocol/protocolVersion"] = ProtocolVersion,
            ["io.modelcontextprotocol/clientCapabilities"] = new Dictionary<string, object?>()
        };

        var body = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 1,
            ["method"] = method,
            ["params"] = parameters
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Accept.ParseAdd("text/event-stream");
        request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", ProtocolVersion);
        request.Headers.TryAddWithoutValidation("Mcp-Method", method);

        if (mcpName is not null)
        {
            request.Headers.TryAddWithoutValidation("Mcp-Name", mcpName);
        }

        if (bearerToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }

        using var response = await httpClient.SendAsync(request);
        var payload = await response.Content.ReadAsStringAsync();

        return JsonSerializer.Deserialize<JsonElement>(ExtractJson(payload));
    }

    /// <summary>Pulls the JSON payload out of a single-event SSE response, or returns it as-is.</summary>
    private static string ExtractJson(string payload)
    {
        foreach (var line in payload.Split('\n'))
        {
            if (line.StartsWith("data:", StringComparison.Ordinal))
            {
                return line["data:".Length..].Trim();
            }
        }

        return payload.Trim();
    }
}
