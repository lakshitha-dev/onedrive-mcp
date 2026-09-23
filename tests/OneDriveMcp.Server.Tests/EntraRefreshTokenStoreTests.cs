using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Server.Auth;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// The store that holds delegated Microsoft access.
/// </summary>
/// <remarks>
/// What is kept here is a long-lived credential for a user's entire OneDrive, so the properties
/// that matter are that it never touches disk in the clear and that it survives a restart —
/// losing it silently signs out every client that registered through Dynamic Client Registration.
/// </remarks>
public sealed class EntraRefreshTokenStoreTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "onedrive-mcp-tests", Guid.NewGuid().ToString("N"));

    private string PersistencePath => Path.Combine(_directory, "entra-refresh-tokens.json");

    public EntraRefreshTokenStoreTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public async Task StoresAndReturnsATokenForAUser()
    {
        using var store = CreateStore();

        await store.SetAsync("user-one", "refresh-token-1", default);

        Assert.Equal("refresh-token-1", await store.GetAsync("user-one", default));
    }

    [Fact]
    public async Task ReturnsNullForAUserWithNoStoredAccess()
    {
        using var store = CreateStore();

        Assert.Null(await store.GetAsync("nobody", default));
    }

    [Fact]
    public async Task KeepsUsersSeparate()
    {
        // A mix-up here would serve one user another user's drive.
        using var store = CreateStore();

        await store.SetAsync("user-one", "token-one", default);
        await store.SetAsync("user-two", "token-two", default);

        Assert.Equal("token-one", await store.GetAsync("user-one", default));
        Assert.Equal("token-two", await store.GetAsync("user-two", default));
    }

    [Fact]
    public async Task ReplacesAPreviousTokenOnRotation()
    {
        // Entra rotates the refresh token on use, so the new value has to win.
        using var store = CreateStore();

        await store.SetAsync("user-one", "old-token", default);
        await store.SetAsync("user-one", "new-token", default);

        Assert.Equal("new-token", await store.GetAsync("user-one", default));
    }

    [Fact]
    public async Task RemovesAccessOnRequest()
    {
        using var store = CreateStore();

        await store.SetAsync("user-one", "refresh-token-1", default);
        await store.RemoveAsync("user-one", default);

        Assert.Null(await store.GetAsync("user-one", default));
    }

    [Fact]
    public async Task NeverWritesTheTokenInTheClear()
    {
        // The single most important property here. A readable file is a stolen drive.
        using var store = CreateStore();

        await store.SetAsync("user-one", "super-secret-refresh-token", default);

        var contents = await File.ReadAllTextAsync(PersistencePath);

        Assert.DoesNotContain("super-secret-refresh-token", contents, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SurvivesARestart()
    {
        // Without persistence, restarting would sign out every DCR client with no indication to
        // them that an interactive sign-in is needed again.
        var protectionProvider = CreateProtectionProvider();

        using (var first = CreateStore(protectionProvider))
        {
            await first.SetAsync("user-one", "refresh-token-1", default);
        }

        using var second = CreateStore(protectionProvider);

        Assert.Equal("refresh-token-1", await second.GetAsync("user-one", default));
    }

    [Fact]
    public async Task RemovalIsPersisted()
    {
        var protectionProvider = CreateProtectionProvider();

        using (var first = CreateStore(protectionProvider))
        {
            await first.SetAsync("user-one", "refresh-token-1", default);
            await first.RemoveAsync("user-one", default);
        }

        using var second = CreateStore(protectionProvider);

        Assert.Null(await second.GetAsync("user-one", default));
    }

    [Fact]
    public async Task DiscardsEntriesItCanNoLongerDecrypt()
    {
        // If the data protection keyring changes, old entries are unreadable for good. Dropping
        // them makes the next request ask for a fresh sign-in instead of failing repeatedly.
        using (var first = CreateStore(CreateProtectionProvider()))
        {
            await first.SetAsync("user-one", "refresh-token-1", default);
        }

        using var withDifferentKeys = CreateStore(CreateProtectionProvider());

        Assert.Null(await withDifferentKeys.GetAsync("user-one", default));
    }

    [Fact]
    public async Task ToleratesACorruptedStoreFile()
    {
        // Unreadable state costs a re-consent, which is recoverable. Refusing to start is not.
        await File.WriteAllTextAsync(PersistencePath, "{ this is not valid json");

        using var store = CreateStore();

        Assert.Null(await store.GetAsync("user-one", default));

        await store.SetAsync("user-one", "refresh-token-1", default);

        Assert.Equal("refresh-token-1", await store.GetAsync("user-one", default));
    }

    [Fact]
    public async Task PersistenceCanBeDisabled()
    {
        using var store = CreateStore(persistencePath: string.Empty);

        await store.SetAsync("user-one", "refresh-token-1", default);

        Assert.Equal("refresh-token-1", await store.GetAsync("user-one", default));
        Assert.False(File.Exists(PersistencePath));
    }

    private EntraRefreshTokenStore CreateStore(
        IDataProtectionProvider? protectionProvider = null,
        string? persistencePath = null)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OAuthServer:EntraTokenPath"] = persistencePath ?? PersistencePath
            })
            .Build();

        return new EntraRefreshTokenStore(
            protectionProvider ?? CreateProtectionProvider(),
            configuration,
            NullLogger<EntraRefreshTokenStore>.Instance);
    }

    /// <summary>A keyring isolated per call, so key rotation can be simulated.</summary>
    private IDataProtectionProvider CreateProtectionProvider()
    {
        var services = new ServiceCollection();

        services.AddDataProtection()
            .SetApplicationName("OneDriveMcp.Tests")
            .PersistKeysToFileSystem(new DirectoryInfo(
                Path.Combine(_directory, "keys", Guid.NewGuid().ToString("N"))));

        return services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test run over.
        }
    }
}
