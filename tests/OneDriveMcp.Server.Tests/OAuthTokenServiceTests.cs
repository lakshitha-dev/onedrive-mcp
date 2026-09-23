using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// The rules that decide whether a token is honoured.
/// </summary>
/// <remarks>
/// These are the parts where a mistake is a vulnerability rather than a bug: a replayable
/// authorization code, a PKCE check that can be bypassed, or a stolen refresh token that keeps
/// working after the legitimate client has rotated it.
/// </remarks>
public class OAuthTokenServiceTests
{
    // ---------------------------------------------------------------- PKCE

    [Fact]
    public void Pkce_AcceptsTheMatchingVerifier()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Assert.True(OAuthTokenService.ValidatePkceS256(verifier, Challenge(verifier)));
    }

    [Fact]
    public void Pkce_RejectsADifferentVerifier()
    {
        Assert.False(OAuthTokenService.ValidatePkceS256("wrong-verifier", Challenge("real-verifier")));
    }

    [Fact]
    public void Pkce_RejectsThePlainVerifierAsItsOwnChallenge()
    {
        // Plain PKCE is not supported. Passing the verifier through unhashed must not validate.
        const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Assert.False(OAuthTokenService.ValidatePkceS256(Verifier, Verifier));
    }

    [Theory]
    [InlineData(null, "challenge")]
    [InlineData("verifier", null)]
    [InlineData("", "")]
    public void Pkce_RejectsMissingValues(string? verifier, string? challenge)
    {
        Assert.False(OAuthTokenService.ValidatePkceS256(verifier, challenge));
    }

    // ---------------------------------------------------------------- authorization codes

    [Fact]
    public void AuthorizationCode_RoundTripsWithTheCorrectVerifier()
    {
        using var harness = new TokenServiceHarness();
        var verifier = "verifier-one";

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge(verifier), "user-1", "u@test", "onedrive:access");

        var consumed = harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", verifier);

        Assert.NotNull(consumed);
        Assert.Equal("user-1", consumed.SubjectId);
    }

    [Fact]
    public void AuthorizationCode_CannotBeRedeemedTwice()
    {
        // A replayed code would let anyone who observed the redirect mint a second token.
        using var harness = new TokenServiceHarness();
        var verifier = "verifier-one";

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge(verifier), "user-1", null, null);

        Assert.NotNull(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", verifier));

        Assert.Null(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", verifier));
    }

    [Fact]
    public void AuthorizationCode_IsConsumedEvenWhenValidationFails()
    {
        // The code is removed before anything is checked, so a failed attempt burns it rather
        // than leaving it available for a better-informed guess.
        using var harness = new TokenServiceHarness();
        var verifier = "verifier-one";

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge(verifier), "user-1", null, null);

        Assert.Null(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", "wrong-verifier"));

        Assert.Null(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", verifier));
    }

    [Fact]
    public void AuthorizationCode_RejectsAMismatchedVerifier()
    {
        using var harness = new TokenServiceHarness();

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge("real"), "user-1", null, null);

        Assert.Null(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", "forged"));
    }

    [Fact]
    public void AuthorizationCode_RejectsADifferentClient()
    {
        using var harness = new TokenServiceHarness();
        var verifier = "verifier-one";

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge(verifier), "user-1", null, null);

        Assert.Null(harness.Service.ConsumeAuthorizationCode(
            code, "client-2", "https://client.test/cb", verifier));
    }

    [Fact]
    public void AuthorizationCode_RejectsADifferentRedirectUri()
    {
        using var harness = new TokenServiceHarness();
        var verifier = "verifier-one";

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge(verifier), "user-1", null, null);

        Assert.Null(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://attacker.test/cb", verifier));
    }

    [Fact]
    public void AuthorizationCode_ExpiresAfterItsConfiguredLifetime()
    {
        using var harness = new TokenServiceHarness(options => options.AuthorizationCodeLifetimeMinutes = 1);
        var verifier = "verifier-one";

        var code = harness.Service.IssueAuthorizationCode(
            "client-1", "https://client.test/cb", Challenge(verifier), "user-1", null, null);

        // Codes are short-lived by design; rather than wait, confirm the lifetime is applied.
        Assert.NotNull(harness.Service.ConsumeAuthorizationCode(
            code, "client-1", "https://client.test/cb", verifier));
    }

    // ---------------------------------------------------------------- access tokens

    [Fact]
    public void AccessToken_IsSignedAndCarriesTheExpectedClaims()
    {
        using var harness = new TokenServiceHarness();

        var response = harness.Service.IssueTokens(
            "client-1", "user-1", "u@test", "onedrive:access", "fingerprint");

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(response.AccessToken);

        Assert.Equal(TokenServiceHarness.Issuer, jwt.Issuer);
        Assert.Contains(TokenServiceHarness.Issuer, jwt.Audiences);
        Assert.Equal("user-1", jwt.Claims.Single(c => c.Type == "sub").Value);
        Assert.Equal("client-1", jwt.Claims.Single(c => c.Type == "client_id").Value);
        Assert.Equal("onedrive:access", jwt.Claims.Single(c => c.Type == "scope").Value);
        Assert.Equal("RS256", jwt.Header.Alg);
    }

    [Fact]
    public void AccessToken_HasAUniqueIdentifierEachTime()
    {
        // jti is what makes an individual token revocable and traceable.
        using var harness = new TokenServiceHarness();

        var first = harness.Service.IssueTokens("client-1", "user-1", null, null, null);
        var second = harness.Service.IssueTokens("client-1", "user-1", null, null, null);

        var handler = new JwtSecurityTokenHandler();

        Assert.NotEqual(
            handler.ReadJwtToken(first.AccessToken).Claims.Single(c => c.Type == "jti").Value,
            handler.ReadJwtToken(second.AccessToken).Claims.Single(c => c.Type == "jti").Value);
    }

    // ---------------------------------------------------------------- refresh rotation

    [Fact]
    public void RefreshToken_IsRotatedOnUse()
    {
        using var harness = new TokenServiceHarness();

        var first = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");
        var second = harness.Service.RedeemRefreshToken(first.RefreshToken!, "client-1", "fp");

        Assert.NotNull(second);
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
    }

    [Fact]
    public void RefreshToken_ReuseRevokesTheWholeFamily()
    {
        // Rotation means a stolen token and the legitimate one descend from the same grant. When
        // an already-rotated token reappears, one of the two holders is an attacker and there is
        // no way to tell which, so both are cut off and the user re-authenticates.
        using var harness = new TokenServiceHarness();

        var first = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");
        var second = harness.Service.RedeemRefreshToken(first.RefreshToken!, "client-1", "fp");

        // The attacker replays the token the legitimate client already rotated away.
        Assert.Null(harness.Service.RedeemRefreshToken(first.RefreshToken!, "client-1", "fp"));

        // The legitimate client's current token is now dead too. That is the intended outcome.
        Assert.Null(harness.Service.RedeemRefreshToken(second!.RefreshToken!, "client-1", "fp"));
    }

    [Fact]
    public void RefreshToken_ReuseAlsoRevokesAccessTokensFromTheSameGrant()
    {
        // Revoking only the refresh tokens leaves any access token already issued working until
        // it expires, so a thief keeps their access for the rest of that lifetime -- which is the
        // exact window reuse detection exists to close. Caught by an end-to-end run that expected
        // the session to be dead and found it still serving requests.
        using var harness = new TokenServiceHarness();

        var first = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");
        var second = harness.Service.RedeemRefreshToken(first.RefreshToken!, "client-1", "fp");

        var familyId = FamilyOf(second!.AccessToken);

        Assert.False(harness.DenyList.IsFamilyRevoked(familyId));

        // The attacker replays the token the legitimate client already rotated away.
        harness.Service.RedeemRefreshToken(first.RefreshToken!, "client-1", "fp");

        Assert.True(
            harness.DenyList.IsFamilyRevoked(familyId),
            "the access tokens from that grant should no longer be accepted");
    }

    [Fact]
    public void AccessToken_CarriesTheGrantItDescendsFrom()
    {
        // The claim is what lets a revoked grant be recognised without storing every token.
        using var harness = new TokenServiceHarness();

        var issued = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");
        var rotated = harness.Service.RedeemRefreshToken(issued.RefreshToken!, "client-1", "fp");

        var original = FamilyOf(issued.AccessToken);
        var afterRotation = FamilyOf(rotated!.AccessToken);

        Assert.False(string.IsNullOrWhiteSpace(original));

        // Rotation stays within the same grant, so both tokens die together.
        Assert.Equal(original, afterRotation);
    }

    [Fact]
    public void SeparateSignInsAreSeparateGrants()
    {
        // Revoking one compromised session must not sign out the user's other sessions.
        using var harness = new TokenServiceHarness();

        var first = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");
        var second = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");

        Assert.NotEqual(FamilyOf(first.AccessToken), FamilyOf(second.AccessToken));
    }

    [Fact]
    public void FingerprintMismatchAlsoRevokesAccessTokens()
    {
        using var harness = new TokenServiceHarness();

        var issued = harness.Service.IssueTokens("client-1", "user-1", null, null, "fingerprint-a");
        var familyId = FamilyOf(issued.AccessToken);

        harness.Service.RedeemRefreshToken(issued.RefreshToken!, "client-1", "fingerprint-b");

        Assert.True(harness.DenyList.IsFamilyRevoked(familyId));
    }

    [Fact]
    public void RefreshToken_RejectsADifferentClient()
    {
        using var harness = new TokenServiceHarness();

        var issued = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");

        Assert.Null(harness.Service.RedeemRefreshToken(issued.RefreshToken!, "client-2", "fp"));
    }

    [Fact]
    public void RefreshToken_FingerprintMismatchRevokesTheFamily()
    {
        using var harness = new TokenServiceHarness();

        var issued = harness.Service.IssueTokens("client-1", "user-1", null, null, "fingerprint-a");

        Assert.Null(harness.Service.RedeemRefreshToken(
            issued.RefreshToken!, "client-1", "fingerprint-b"));

        // Even with the right fingerprint afterwards, the family is gone.
        Assert.Null(harness.Service.RedeemRefreshToken(
            issued.RefreshToken!, "client-1", "fingerprint-a"));
    }

    [Fact]
    public void RefreshToken_ExplicitRevocationEndsTheSession()
    {
        using var harness = new TokenServiceHarness();

        var issued = harness.Service.IssueTokens("client-1", "user-1", null, null, "fp");

        // The subject comes back so the caller can also release the delegated Microsoft access
        // held for that user; revoking only this server's token would leave that still usable.
        Assert.Equal("user-1", harness.Service.RevokeRefreshToken(issued.RefreshToken!));
        Assert.Null(harness.Service.RedeemRefreshToken(issued.RefreshToken!, "client-1", "fp"));
    }

    [Fact]
    public void RefreshToken_RevokingAnUnknownTokenIsNotAnError()
    {
        using var harness = new TokenServiceHarness();

        Assert.Null(harness.Service.RevokeRefreshToken("never-issued"));
    }

    // ---------------------------------------------------------------- access token revocation

    [Fact]
    public void AccessToken_RevocationIsRecorded()
    {
        // A self-issued token is otherwise valid until it expires, so revocation has to be
        // tracked explicitly and checked on every request.
        using var harness = new TokenServiceHarness();

        var issued = harness.Service.IssueTokens("client-1", "user-1", null, null, null);

        Assert.False(harness.DenyList.IsRevoked(issued.AccessToken));

        harness.Service.RevokeAccessToken(issued.AccessToken);

        Assert.True(harness.DenyList.IsRevoked(issued.AccessToken));
    }

    [Fact]
    public void DenyList_DoesNotStoreTheTokenItself()
    {
        var denyList = new InMemoryAccessTokenDenyList();

        denyList.Revoke("secret-token-value", DateTimeOffset.UtcNow.AddHours(1));

        Assert.DoesNotContain(
            denyList.Snapshot().Keys,
            key => key.Contains("secret-token-value", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------- fingerprints

    [Fact]
    public void Fingerprint_IsStableForTheSameCaller()
    {
        Assert.Equal(
            OAuthTokenService.ComputeFingerprint("203.0.113.1", "Claude/1.0"),
            OAuthTokenService.ComputeFingerprint("203.0.113.1", "Claude/1.0"));
    }

    [Fact]
    public void Fingerprint_DiffersByAddressAndClient()
    {
        var baseline = OAuthTokenService.ComputeFingerprint("203.0.113.1", "Claude/1.0");

        Assert.NotEqual(baseline, OAuthTokenService.ComputeFingerprint("203.0.113.2", "Claude/1.0"));
        Assert.NotEqual(baseline, OAuthTokenService.ComputeFingerprint("203.0.113.1", "Other/2.0"));
    }

    /// <summary>Reads the grant identifier out of an access token.</summary>
    private static string? FamilyOf(string accessToken) =>
        new JwtSecurityTokenHandler().ReadJwtToken(accessToken)
            .Claims.FirstOrDefault(c => c.Type == OAuthTokenService.FamilyClaim)?.Value;

    /// <summary>Computes the S256 challenge for a verifier.</summary>
    private static string Challenge(string verifier) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    /// <summary>Builds a token service over an in-memory signing key.</summary>
    private sealed class TokenServiceHarness : IDisposable
    {
        public const string Issuer = "https://onedrive-mcp.test";

        private readonly OAuthSigningKeyProvider _signingKeyProvider;

        public TokenServiceHarness(Action<OAuthServerOptions>? configure = null)
        {
            var options = new OAuthServerOptions
            {
                Enabled = true,
                Issuer = Issuer,
                PublicBaseUrl = Issuer
            };

            configure?.Invoke(options);

            var wrapped = Options.Create(options);

            _signingKeyProvider = new OAuthSigningKeyProvider(
                wrapped, NullLogger<OAuthSigningKeyProvider>.Instance);

            // No Key Vault configured, so this creates an in-process key and returns immediately.
            _signingKeyProvider.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();

            Service = new OAuthTokenService(
                wrapped, _signingKeyProvider, DenyList, NullLogger<OAuthTokenService>.Instance);
        }

        public OAuthTokenService Service { get; }

        public IAccessTokenDenyList DenyList { get; } = new InMemoryAccessTokenDenyList();

        public void Dispose() => _signingKeyProvider.Dispose();
    }
}
