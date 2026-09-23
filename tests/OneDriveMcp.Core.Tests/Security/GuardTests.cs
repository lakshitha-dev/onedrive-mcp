using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Core.Tests.Security;

public class ODataEscaperTests
{
    [Theory]
    [InlineData("O'Brien", "O''Brien")]
    [InlineData("it's", "it''s")]
    [InlineData("''", "''''")]
    [InlineData("plain text", "plain text")]
    public void EscapeStringLiteral_DoublesApostrophes(string input, string expected)
    {
        Assert.Equal(expected, ODataEscaper.EscapeStringLiteral(input));
    }

    [Fact]
    public void EscapeStringLiteral_NeutralisesAttemptsToCloseTheLiteral()
    {
        // Unescaped, this would terminate the literal and the rest would be parsed as OData.
        var escaped = ODataEscaper.EscapeStringLiteral("x') or startswith(name,'");

        Assert.Equal("x'') or startswith(name,''", escaped);

        // Every apostrophe must appear in an even-length run: a lone one would still close the
        // literal. Checking runs rather than substrings, because the escaped form legitimately
        // contains the original text with each quote doubled.
        Assert.All(ApostropheRunLengths(escaped), length => Assert.Equal(0, length % 2));
    }

    /// <summary>Lengths of each run of consecutive apostrophes in a string.</summary>
    private static IEnumerable<int> ApostropheRunLengths(string value)
    {
        var run = 0;

        foreach (var character in value)
        {
            if (character == '\'')
            {
                run++;
            }
            else if (run > 0)
            {
                yield return run;
                run = 0;
            }
        }

        if (run > 0)
        {
            yield return run;
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void EscapeStringLiteral_HandlesEmptyInput(string? input)
    {
        Assert.Equal(string.Empty, ODataEscaper.EscapeStringLiteral(input));
    }

    [Theory]
    [InlineData("line\nbreak")]
    [InlineData("tab\there")]
    [InlineData("null\0byte")]
    public void EscapeStringLiteral_RejectsControlCharacters(string input)
    {
        Assert.Throws<ArgumentException>(() => ODataEscaper.EscapeStringLiteral(input));
    }
}

public class GraphUrlGuardTests
{
    [Theory]
    [InlineData("https://graph.microsoft.com/v1.0/me/drive")]
    [InlineData("https://contoso-my.sharepoint.com/personal/x/file.pdf")]
    [InlineData("https://abc.files.1drv.com/content")]
    [InlineData("https://xyz.up.svc.ms/session/1")]
    public void IsAllowed_AcceptsMicrosoftContentHosts(string url)
    {
        Assert.True(GraphUrlGuard.IsAllowed(url));
    }

    [Theory]
    [InlineData("https://evil.example.com/steal")]
    [InlineData("https://sharepoint.com.evil.example.com/steal")]
    [InlineData("https://evil-sharepoint.com/steal")]
    [InlineData("https://files.1drv.com.attacker.net/x")]
    [InlineData("http://contoso-my.sharepoint.com/insecure")]
    [InlineData("file:///C:/windows/win.ini")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a url")]
    public void IsAllowed_RejectsEverythingElse(string? url)
    {
        Assert.False(GraphUrlGuard.IsAllowed(url));
    }

    [Fact]
    public void EnsureAllowed_ThrowsForADisallowedHost()
    {
        Assert.Throws<InvalidOperationException>(
            () => GraphUrlGuard.EnsureAllowed("https://evil.example.com/steal"));
    }

    [Fact]
    public void EnsureAllowed_ReturnsTheUrlWhenPermitted()
    {
        const string Url = "https://contoso-my.sharepoint.com/f.pdf";

        Assert.Equal(Url, GraphUrlGuard.EnsureAllowed(Url));
    }
}
