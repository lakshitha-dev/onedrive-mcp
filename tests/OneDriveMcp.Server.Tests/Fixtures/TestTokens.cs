using System.Text;
using System.Text.Json;

namespace OneDriveMcp.Server.Tests.Fixtures;

/// <summary>Builds unsigned JWTs for tests. Signature validation is not exercised here.</summary>
internal static class TestTokens
{
    public static string Entra(string oid, string tenant = "test-tenant") =>
        Build(new Dictionary<string, object>
        {
            ["oid"] = oid,
            ["iss"] = $"https://login.microsoftonline.com/{tenant}/v2.0"
        });

    public static string SelfIssued(string subject, string issuer = "https://onedrive-mcp.test") =>
        Build(new Dictionary<string, object>
        {
            ["sub"] = subject,
            ["iss"] = issuer
        });

    private static string Build(Dictionary<string, object> payload)
    {
        static string Segment(object value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Segment(new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT" });
        return $"{header}.{Segment(payload)}.signature";
    }
}
