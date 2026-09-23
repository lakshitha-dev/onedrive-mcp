using OneDriveMcp.Server.OAuth.Endpoints;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// The Content-Security-Policy on the consent page.
/// </summary>
/// <remarks>
/// This has a failure mode worth guarding carefully. Browsers apply <c>form-action</c> to the
/// redirect that follows a form submission, not only its immediate target, so a policy of
/// <c>'self'</c> alone stops the browser delivering the authorization code to the client. The
/// server logs a granted consent and a correct 302; the client simply never receives anything.
/// Nothing looks wrong from the server side, which is what made it expensive to find.
/// </remarks>
public class ConsentPagePolicyTests
{
    [Theory]
    [InlineData("http://localhost:9876/callback/", "http://localhost:9876")]
    [InlineData("https://client.example.com/oauth/callback", "https://client.example.com")]
    [InlineData("https://client.example.com:8443/cb", "https://client.example.com:8443")]
    [InlineData("http://127.0.0.1:5173/callback", "http://127.0.0.1:5173")]
    public void FormActionAllowsTheClientOrigin(string redirectUri, string expectedOrigin)
    {
        var policy = AuthorizeEndpoint.BuildConsentCsp(redirectUri);

        Assert.Contains($"form-action 'self' {expectedOrigin};", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void FormActionCarriesOnlyTheOriginNotThePath()
    {
        // A path in a form-action source is ignored by browsers and only adds noise; the origin
        // is what governs whether the redirect is permitted.
        var policy = AuthorizeEndpoint.BuildConsentCsp("https://client.example.com/oauth/callback");

        Assert.DoesNotContain("/oauth/callback", policy, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-absolute-uri")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<h1>x</h1>")]
    public void UnusableRedirectsFallBackToSelfOnly(string? redirectUri)
    {
        // Falling back closed matters: a scheme like javascript: or data: must never reach a
        // form-action source list.
        var policy = AuthorizeEndpoint.BuildConsentCsp(redirectUri);

        Assert.Contains("form-action 'self';", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("javascript:", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("data:", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyStillLocksDownEverythingElse()
    {
        var policy = AuthorizeEndpoint.BuildConsentCsp("https://client.example.com/cb");

        // The page loads nothing and may not be framed. Only inline styles are permitted, for
        // the page's own stylesheet.
        Assert.Contains("default-src 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("style-src 'unsafe-inline'", policy, StringComparison.Ordinal);

        // Nothing should be able to run script on a page that grants access to a drive.
        Assert.DoesNotContain("script-src", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void ADifferentClientOriginIsNotPermitted()
    {
        // The origin comes from the registration that was matched moments earlier, so one
        // client's consent page cannot post to another's address.
        var policy = AuthorizeEndpoint.BuildConsentCsp("https://client-a.example.com/cb");

        Assert.DoesNotContain("client-b.example.com", policy, StringComparison.Ordinal);
    }
}
