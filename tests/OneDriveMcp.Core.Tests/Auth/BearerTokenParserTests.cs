using System.Text;
using System.Text.Json;
using OneDriveMcp.Core.Auth;

namespace OneDriveMcp.Core.Tests.Auth;

/// <summary>
/// The Entra / self-issued distinction decides whether a credential can be exchanged by
/// on-behalf-of or has to go through the stored Entra refresh token. Getting it wrong means
/// every Graph call from a DCR client fails, so it is pinned down here.
/// </summary>
public class BearerTokenParserTests
{
    [Fact]
    public void TryParse_EntraV2Token_IsRecognisedAsEntra()
    {
        var token = Jwt(new Dictionary<string, object>
        {
            ["oid"] = "11111111-1111-1111-1111-111111111111",
            ["sub"] = "ignored-when-oid-present",
            ["iss"] = "https://login.microsoftonline.com/tenant/v2.0"
        });

        var credential = BearerTokenParser.TryParse(token);

        Assert.NotNull(credential);
        Assert.True(credential.IsEntra);
        Assert.Equal("11111111-1111-1111-1111-111111111111", credential.Subject);
        Assert.Equal(token, credential.RawToken);
    }

    [Fact]
    public void TryParse_EntraV1Token_IsRecognisedAsEntra()
    {
        var credential = BearerTokenParser.TryParse(Jwt(new Dictionary<string, object>
        {
            ["oid"] = "abc",
            ["iss"] = "https://sts.windows.net/tenant/"
        }));

        Assert.NotNull(credential);
        Assert.True(credential.IsEntra);
    }

    [Fact]
    public void TryParse_SelfIssuedToken_IsNotEntra()
    {
        // A token minted by this server's own DCR endpoint. Entra rejects it as an OBO
        // assertion, so it must not be mistaken for one.
        var credential = BearerTokenParser.TryParse(Jwt(new Dictionary<string, object>
        {
            ["sub"] = "dcr-client",
            ["iss"] = "https://onedrive-mcp.example.com"
        }));

        Assert.NotNull(credential);
        Assert.False(credential.IsEntra);
        Assert.Equal("dcr-client", credential.Subject);
    }

    [Fact]
    public void TryParse_PrefersOidOverSub()
    {
        // oid is stable per user; sub is only unique per (user, application) pair. The Graph
        // token cache and the Entra refresh-token store must key on the same identity.
        var credential = BearerTokenParser.TryParse(Jwt(new Dictionary<string, object>
        {
            ["oid"] = "the-oid",
            ["sub"] = "the-sub",
            ["iss"] = "https://login.microsoftonline.com/t/v2.0"
        }));

        Assert.Equal("the-oid", credential!.Subject);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-jwt")]
    [InlineData("still.not.a.jwt.at.all")]
    public void TryParse_NonToken_ReturnsNull(string? value)
    {
        Assert.Null(BearerTokenParser.TryParse(value));
    }

    [Theory]
    [InlineData("Bearer abc", "abc")]
    [InlineData("bearer abc", "abc")]
    [InlineData("BEARER   abc  ", "abc")]
    public void StripBearerPrefix_RemovesSchemeCaseInsensitively(string header, string expected)
    {
        Assert.Equal(expected, BearerTokenParser.StripBearerPrefix(header));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]          // no scheme
    [InlineData("Basic abc")]    // wrong scheme
    [InlineData("Bearer ")]      // scheme but no value
    public void StripBearerPrefix_RejectsAnythingElse(string? header)
    {
        Assert.Null(BearerTokenParser.StripBearerPrefix(header));
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com/t/v2.0", true)]
    [InlineData("https://sts.windows.net/t/", true)]
    [InlineData("https://LOGIN.MICROSOFTONLINE.COM/t/v2.0", true)]
    [InlineData("https://evil.com/https://login.microsoftonline.com/", false)]
    [InlineData("https://login.microsoftonline.com.evil.com/t/", false)]
    [InlineData("http://localhost:5170", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    public void IsEntraIssuer_MatchesOnPrefixOnly(string? issuer, bool expected)
    {
        Assert.Equal(expected, BearerTokenParser.IsEntraIssuer(issuer));
    }

    /// <summary>Builds an unsigned JWT. Signature validation is JwtBearer's job, not the parser's.</summary>
    private static string Jwt(Dictionary<string, object> payload)
    {
        static string Segment(object value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Segment(new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT" });
        return $"{header}.{Segment(payload)}.signature";
    }
}
