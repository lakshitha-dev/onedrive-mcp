using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// What the authorization server remembers across a restart.
/// </summary>
/// <remarks>
/// The revoked-token entries are the reason this exists. Everything else being forgotten is
/// disruptive -- clients re-register, users sign in again -- but a forgotten revocation means a
/// token someone deliberately killed starts working again, and on App Service a restart is a
/// routine event rather than an exceptional one.
/// </remarks>
public sealed class OAuthStatePersistenceTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "onedrive-mcp-oauth-state", Guid.NewGuid().ToString("N"));

    private string StatePath => Path.Combine(_directory, "oauth-state.json");

    public OAuthStatePersistenceTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task RevokedTokensSurviveARestart()
    {
        var protection = CreateProtectionProvider();
        const string Token = "an-access-token-that-was-revoked";

        var before = CreateHarness(protection);
        await before.Persistence.StartAsync(default);
        before.DenyList.Revoke(Token, DateTimeOffset.UtcNow.AddHours(1));
        await before.Persistence.StopAsync(default);

        var after = CreateHarness(protection);
        await after.Persistence.StartAsync(default);

        Assert.True(
            after.DenyList.IsRevoked(Token),
            "a revoked token must not start working again after a restart");
    }

    [Fact]
    public async Task RevokedGrantsSurviveARestart()
    {
        var protection = CreateProtectionProvider();
        const string FamilyId = "grant-1";

        var before = CreateHarness(protection);
        await before.Persistence.StartAsync(default);
        before.DenyList.RevokeFamily(FamilyId, DateTimeOffset.UtcNow.AddHours(1));
        await before.Persistence.StopAsync(default);

        var after = CreateHarness(protection);
        await after.Persistence.StartAsync(default);

        Assert.True(after.DenyList.IsFamilyRevoked(FamilyId));
    }

    [Fact]
    public async Task RegisteredClientsSurviveARestart()
    {
        // Otherwise every connected MCP client silently breaks on each deploy and has to register
        // and sign in again, with nothing to tell it why.
        var protection = CreateProtectionProvider();

        var before = CreateHarness(protection);
        await before.Persistence.StartAsync(default);
        before.ClientStore.Add(new OAuth.Models.OAuthClientRegistration
        {
            ClientId = "client-1",
            ClientName = "Test Client",
            RedirectUris = ["https://client.test/cb"],
            TokenEndpointAuthMethod = "none"
        });
        await before.Persistence.StopAsync(default);

        var after = CreateHarness(protection);
        await after.Persistence.StartAsync(default);

        var restored = after.ClientStore.Find("client-1");

        Assert.NotNull(restored);
        Assert.Equal("Test Client", restored.ClientName);
        Assert.Equal(["https://client.test/cb"], restored.RedirectUris);
    }

    [Fact]
    public async Task RefreshTokensSurviveARestart()
    {
        var protection = CreateProtectionProvider();

        var before = CreateHarness(protection);
        await before.Persistence.StartAsync(default);
        var issued = before.TokenService.IssueTokens("client-1", "user-1", null, "onedrive:access", "fp");
        await before.Persistence.StopAsync(default);

        var after = CreateHarness(protection);
        await after.Persistence.StartAsync(default);

        var redeemed = after.TokenService.RedeemRefreshToken(issued.RefreshToken!, "client-1", "fp");

        Assert.NotNull(redeemed);
    }

    [Fact]
    public async Task TheStateFileIsNotReadableAsPlainText()
    {
        // It holds refresh tokens, which are long-lived credentials for real drives.
        var harness = CreateHarness(CreateProtectionProvider());
        await harness.Persistence.StartAsync(default);

        harness.ClientStore.Add(new OAuth.Models.OAuthClientRegistration
        {
            ClientId = "a-recognisable-client-id",
            RedirectUris = ["https://client.test/cb"],
            TokenEndpointAuthMethod = "none"
        });

        await harness.Persistence.StopAsync(default);

        var contents = await File.ReadAllTextAsync(StatePath);

        Assert.DoesNotContain("a-recognisable-client-id", contents, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredEntriesAreNotRestored()
    {
        // Carrying them forward would grow the file without bound, and they are moot anyway --
        // the tokens they refer to would fail on their own lifetime.
        var protection = CreateProtectionProvider();

        var before = CreateHarness(protection);
        await before.Persistence.StartAsync(default);
        before.DenyList.Revoke("already-expired", DateTimeOffset.UtcNow.AddSeconds(-1));
        await before.Persistence.StopAsync(default);

        var after = CreateHarness(protection);
        await after.Persistence.StartAsync(default);

        Assert.False(after.DenyList.IsRevoked("already-expired"));
    }

    [Fact]
    public async Task AnUnreadableFileDoesNotStopTheServerStarting()
    {
        // Starting empty costs a round of re-registration, which is recoverable. Refusing to
        // start is not.
        await File.WriteAllTextAsync(StatePath, "this is not encrypted json");

        var harness = CreateHarness(CreateProtectionProvider());

        await harness.Persistence.StartAsync(default);

        Assert.Null(harness.ClientStore.Find("anything"));
    }

    [Fact]
    public async Task FlushWritesImmediately()
    {
        // Revocation calls this rather than waiting for the periodic save, because a crash in
        // that window would resurrect the token.
        var harness = CreateHarness(CreateProtectionProvider());
        await harness.Persistence.StartAsync(default);

        Assert.False(File.Exists(StatePath));

        harness.DenyList.Revoke("token", DateTimeOffset.UtcNow.AddHours(1));
        await harness.Persistence.FlushAsync(default);

        Assert.True(File.Exists(StatePath));
    }

    [Fact]
    public async Task PersistenceCanBeDisabled()
    {
        var harness = CreateHarness(CreateProtectionProvider(), persistencePath: string.Empty);

        await harness.Persistence.StartAsync(default);
        await harness.Persistence.StopAsync(default);

        Assert.False(File.Exists(StatePath));
    }

    private Harness CreateHarness(IDataProtectionProvider protection, string? persistencePath = null)
    {
        var options = Options.Create(new OAuthServerOptions
        {
            Enabled = true,
            Issuer = "https://onedrive-mcp.test",
            PublicBaseUrl = "https://onedrive-mcp.test",
            PersistencePath = persistencePath ?? StatePath
        });

        var signingKeys = new OAuthSigningKeyProvider(options, NullLogger<OAuthSigningKeyProvider>.Instance);
        signingKeys.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();

        var clientStore = new InMemoryOAuthClientStore();
        var denyList = new InMemoryAccessTokenDenyList();
        var tokenService = new OAuthTokenService(
            options, signingKeys, denyList, NullLogger<OAuthTokenService>.Instance);

        var persistence = new OAuthStatePersistence(
            clientStore, denyList, tokenService, protection, options,
            NullLogger<OAuthStatePersistence>.Instance);

        return new Harness(clientStore, denyList, tokenService, persistence);
    }

    /// <summary>A keyring per call, so a "different deployment" can be simulated.</summary>
    private IDataProtectionProvider CreateProtectionProvider()
    {
        var services = new ServiceCollection();

        services.AddDataProtection()
            .SetApplicationName("OneDriveMcp.Tests")
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(_directory, "keys")));

        return services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
    }

    private sealed record Harness(
        IOAuthClientStore ClientStore,
        IAccessTokenDenyList DenyList,
        OAuthTokenService TokenService,
        OAuthStatePersistence Persistence);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a run over.
        }
    }
}
