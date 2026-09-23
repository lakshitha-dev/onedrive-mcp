using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Models;

namespace OneDriveMcp.Server.OAuth.Services;

/// <summary>The authorization server state that has to outlive the process.</summary>
internal sealed class PersistedOAuthState
{
    /// <summary>Clients registered through Dynamic Client Registration.</summary>
    public List<OAuthClientRegistration> Clients { get; set; } = [];

    /// <summary>Outstanding refresh tokens.</summary>
    public List<RefreshTokenEntity> RefreshTokens { get; set; } = [];

    /// <summary>Hashes of revoked access tokens, and when they would expire anyway.</summary>
    public Dictionary<string, DateTimeOffset> RevokedTokens { get; set; } = [];

    /// <summary>Revoked grants, and when their last possible token expires.</summary>
    public Dictionary<string, DateTimeOffset> RevokedFamilies { get; set; } = [];
}

/// <summary>
/// Keeps the authorization server's state across restarts.
/// </summary>
/// <remarks>
/// <para>
/// Without this the server forgets, on every restart, which clients are registered, which refresh
/// tokens are live, and -- most seriously -- which access tokens have been revoked. A revoked
/// token would start working again the moment the app recycled, which on App Service happens
/// routinely. Registered clients disappearing is less dangerous but just as disruptive: every
/// connected MCP client would have to re-register and every user sign in again after a deploy.
/// </para>
/// <para>
/// Authorization codes and consent sessions are deliberately not kept. Both live for minutes and
/// belong to a sign-in that is already in flight; a restart mid-flow is better answered by asking
/// the user to start again than by resurrecting half a handshake.
/// </para>
/// <para>
/// The file holds refresh tokens, so it is encrypted with Data Protection rather than written in
/// the clear, and replaced atomically so a crash part-way through cannot leave a truncated file
/// that fails to decrypt.
/// </para>
/// </remarks>
public sealed class OAuthStatePersistence : IHostedService, IDisposable
{
    private const string ProtectionPurpose = "OneDriveMcp.OAuth.State.v1";

    private static readonly TimeSpan SaveInterval = TimeSpan.FromSeconds(30);

    private readonly IOAuthClientStore _clientStore;
    private readonly IAccessTokenDenyList _denyList;
    private readonly OAuthTokenService _tokenService;
    private readonly IDataProtector _protector;
    private readonly ILogger<OAuthStatePersistence> _logger;
    private readonly string? _path;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private Timer? _timer;
    private bool _disposed;

    /// <summary>Creates the persistence service.</summary>
    public OAuthStatePersistence(
        IOAuthClientStore clientStore,
        IAccessTokenDenyList denyList,
        OAuthTokenService tokenService,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<OAuthServerOptions> options,
        ILogger<OAuthStatePersistence> logger)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(options);

        _clientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
        _denyList = denyList ?? throw new ArgumentNullException(nameof(denyList));
        _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
        _protector = dataProtectionProvider.CreateProtector(ProtectionPurpose);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _path = ResolvePath(options.Value);
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_path is null)
        {
            _logger.LogWarning(
                "OAuth state is not being persisted, so a restart will forget registered clients " +
                "and revoked tokens. Acceptable only for local development.");

            return Task.CompletedTask;
        }

        Load();

        _timer = new Timer(_ => _ = SaveAsync(CancellationToken.None), null, SaveInterval, SaveInterval);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_timer is not null)
        {
            await _timer.DisposeAsync();
            _timer = null;
        }

        // A clean shutdown is the one moment the in-memory state is guaranteed current.
        await SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Writes the current state immediately.
    /// </summary>
    /// <remarks>
    /// Called after a revocation rather than waiting for the timer. Losing thirty seconds of
    /// client registrations to an ill-timed crash is a nuisance; losing a revocation is a
    /// security failure, because the token starts working again.
    /// </remarks>
    public Task FlushAsync(CancellationToken cancellationToken) => SaveAsync(cancellationToken);

    private void Load()
    {
        if (_path is null || !File.Exists(_path))
        {
            return;
        }

        try
        {
            var protectedBytes = File.ReadAllBytes(_path);
            var json = Encoding.UTF8.GetString(_protector.Unprotect(protectedBytes));
            var state = JsonSerializer.Deserialize<PersistedOAuthState>(json);

            if (state is null)
            {
                return;
            }

            _clientStore.Restore(state.Clients);
            _tokenService.RestoreRefreshTokens(state.RefreshTokens);
            _denyList.Restore(state.RevokedTokens);
            _denyList.RestoreFamilies(state.RevokedFamilies);

            _logger.LogInformation(
                "Restored OAuth state: {Clients} client(s), {RefreshTokens} refresh token(s), " +
                "{RevokedTokens} revoked token(s), {RevokedFamilies} revoked grant(s)",
                state.Clients.Count,
                state.RefreshTokens.Count,
                state.RevokedTokens.Count,
                state.RevokedFamilies.Count);
        }
        catch (Exception exception)
            when (exception is IOException or JsonException or System.Security.Cryptography.CryptographicException)
        {
            // Starting with empty state costs everyone a re-registration and a sign-in, which is
            // recoverable. Refusing to start is not. The revoked entries are the uncomfortable
            // part of that trade, so it is logged as an error rather than a warning.
            _logger.LogError(
                exception,
                "Could not read the persisted OAuth state. Registered clients and revoked tokens " +
                "from before this restart are lost; clients will need to register again.");
        }
    }

    private async Task SaveAsync(CancellationToken cancellationToken)
    {
        if (_path is null || _disposed)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken);

        try
        {
            var state = new PersistedOAuthState
            {
                Clients = [.. _clientStore.All()],
                RefreshTokens = [.. _tokenService.SnapshotRefreshTokens()],
                RevokedTokens = new Dictionary<string, DateTimeOffset>(_denyList.Snapshot()),
                RevokedFamilies = new Dictionary<string, DateTimeOffset>(_denyList.SnapshotFamilies())
            };

            var json = JsonSerializer.Serialize(state);
            var protectedBytes = _protector.Protect(Encoding.UTF8.GetBytes(json));

            // Written aside and moved into place, so an interrupted write leaves the previous
            // state intact rather than a partial file that cannot be decrypted.
            var temporaryPath = _path + ".tmp";

            await File.WriteAllBytesAsync(temporaryPath, protectedBytes, cancellationToken);
            File.Move(temporaryPath, _path, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(exception, "Could not persist OAuth state");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Chooses where to persist. On App Service <c>/home</c> is the durable mount that survives
    /// restarts and deploys; a local path is used otherwise. An empty configured value disables
    /// persistence, which the tests rely on.
    /// </summary>
    private static string? ResolvePath(OAuthServerOptions options)
    {
        if (options.PersistencePath is not null)
        {
            return string.IsNullOrWhiteSpace(options.PersistencePath) ? null : options.PersistencePath;
        }

        if (Directory.Exists("/home"))
        {
            var directory = Path.Combine("/home", "data");
            Directory.CreateDirectory(directory);

            return Path.Combine(directory, "oauth-state.json");
        }

        return Path.Combine(AppContext.BaseDirectory, "oauth-state.json");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _timer?.Dispose();
        _writeLock.Dispose();
        _disposed = true;
    }
}
