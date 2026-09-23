using System.Text;
using OneDriveMcp.Core.Graph;

namespace OneDriveMcp.Core.Tests.Graph;

/// <summary>
/// The cursor is a caller-supplied value that becomes a request URL with the caller's Graph
/// bearer token attached. Without the host check that is a way to make the server post the
/// token wherever the caller likes.
/// </summary>
public class PageCursorTests
{
    [Fact]
    public void Encode_ThenDecode_RoundTrips()
    {
        const string NextLink =
            "https://graph.microsoft.com/v1.0/me/drive/root/children?$skiptoken=abc123";

        var cursor = PageCursor.Encode(NextLink);

        Assert.NotNull(cursor);
        Assert.Equal(NextLink, PageCursor.Decode(cursor));
    }

    [Fact]
    public void Encode_ProducesAnOpaqueValue()
    {
        var cursor = PageCursor.Encode("https://graph.microsoft.com/v1.0/me/drive/root/children");

        Assert.DoesNotContain("graph.microsoft.com", cursor, StringComparison.Ordinal);
        Assert.DoesNotContain("://", cursor, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Encode_ReturnsNullWhenThereIsNoNextPage(string? nextLink)
    {
        Assert.Null(PageCursor.Encode(nextLink));
    }

    [Theory]
    [InlineData("https://evil.example.com/steal")]
    [InlineData("http://graph.microsoft.com/v1.0/me")]                   // not HTTPS
    [InlineData("https://graph.microsoft.com.evil.example.com/v1.0")]    // suffix confusion
    [InlineData("file:///C:/windows/win.ini")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]            // cloud metadata endpoint
    public void Decode_RejectsAnythingNotPointingAtGraph(string url)
    {
        var forged = Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Throws<ArgumentException>(() => PageCursor.Decode(forged));
    }

    [Theory]
    [InlineData("not-base64!!")]
    [InlineData("")]
    [InlineData("   ")]
    public void Decode_RejectsMalformedCursors(string cursor)
    {
        Assert.Throws<ArgumentException>(() => PageCursor.Decode(cursor));
    }

    [Fact]
    public void Decode_RejectsAValidCursorThatIsNotAUrl()
    {
        var notAUrl = Convert.ToBase64String(Encoding.UTF8.GetBytes("just some text"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Throws<ArgumentException>(() => PageCursor.Decode(notAUrl));
    }
}
