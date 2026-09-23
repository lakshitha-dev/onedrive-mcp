using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using OneDriveMcp.Core.Auth;

namespace OneDriveMcp.Server.Auth;

/// <summary>
/// Stores Entra refresh tokens, encrypted at rest and persisted across restarts.
/// </summary>
/// <remarks>
/// <para>
/// A refresh token here is long-lived delegated access to a user's whole OneDrive, so it is
/// encrypted with ASP.NET Data Protection rather than written in the clear, and never logged.
/// Losing the file costs users a re-consent; leaking it would cost them their drive.
/// </para>
/// <para>
/// Persisting matters because these are not easily re-obtained: without it, a restart would
/// silently sign out every client that had registered through Dynamic Client Registration, and
/// the only recovery would be an interactive sign-in each of them has no way to know it needs.
/// </para>
/// <para>
/// Writes are serialised through a lock and the file is replaced atomically, so a crash mid-save
/// cannot leave a half-written store that fails to decrypt.
/// </para>
/// </remarks>
public sealed class EntraRefreshTokenStore : IEntraRefreshTokenStore, IDisposable
{
    private const string ProtectionPurpose = "OneDriveMcp.EntraRefreshTokens.v1";

    private readonly ConcurrentDictionary<string, string> _tokens = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly IDataProtector _protector;
    private readonly string? _persistencePath;
    private readonly ILogger<EntraRefreshTokenStore> _logger;

    private bool _disposed;

    /// <summary>Creates the store and loads any persisted state.</summary>
    public EntraRefreshTokenStore(
        IDataProtectionProvider dataProtectionProvider,
        IConfiguration configuration,
        ILogger<EntraRefreshTokenStore> logger)
    {
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(configuration);

        _protector = dataProtectionProvider.CreateProtector(ProtectionPurpose);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _persistencePath = ResolvePersistencePath(configuration);

        Load();
    }

    /// <inheritdoc />
    public Task<string?> GetAsync(string subjectId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subjectId) || !_tokens.TryGetValue(subjectId, out var protectedToken))
        {
            return Task.FromResult<string?>(null);
        }

        try
        {
            return Task.FromResult<string?>(_protector.Unprotect(protectedToken));
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // The data protection keyring changed, so this entry can never be read again.
            // Dropping it makes the next request ask for a fresh sign-in.
            _tokens.TryRemove(subjectId, out _);

            _logger.LogWarning(
                "A stored refresh token could not be decrypted and has been discarded. The user " +
                "will be asked to sign in again.");

            return Task.FromResult<string?>(null);
        }
    }

    /// <inheritdoc />
    public async Task SetAsync(string subjectId, string refreshToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subjectId) || string.IsNullOrEmpty(refreshToken))
        {
            return;
        }

        _tokens[subjectId] = _protector.Protect(refreshToken);

        await SaveAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string subjectId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subjectId) || !_tokens.TryRemove(subjectId, out _))
        {
            return;
        }

        await SaveAsync(cancellationToken);
    }

    private void Load()
    {
        if (_persistencePath is null || !File.Exists(_persistencePath))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(_persistencePath, Encoding.UTF8);
            var stored = JsonSerializer.Deserialize<Dictionary<string, string>>(json);

            if (stored is null)
            {
                return;
            }

            foreach (var (subjectId, protectedToken) in stored)
            {
                _tokens[subjectId] = protectedToken;
            }

            _logger.LogInformation(
                "Restored delegated Microsoft access for {Count} account(s)", _tokens.Count);
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            // Unreadable state costs a re-consent, which is recoverable. Failing to start is not.
            _logger.LogWarning(
                exception,
                "Could not read the stored refresh tokens; affected users will sign in again");
        }
    }

    private async Task SaveAsync(CancellationToken cancellationToken)
    {
        if (_persistencePath is null)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken);

        try
        {
            var json = JsonSerializer.Serialize(
                _tokens.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));

            // Written to a temporary file and moved into place, so a crash part-way through
            // leaves the previous store intact rather than a truncated one that cannot decrypt.
            var tempPath = _persistencePath + ".tmp";

            await File.WriteAllTextAsync(tempPath, json, Encoding.UTF8, cancellationToken);
            File.Move(tempPath, _persistencePath, overwrite: true);
        }
        catch (IOException exception)
        {
            _logger.LogError(
                exception,
                "Could not persist refresh tokens; they will be lost when the server restarts");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Chooses where to persist. On App Service <c>/home</c> is the durable, shared mount; a local
    /// path is used otherwise. An empty configured value disables persistence, which the tests use.
    /// </summary>
    private static string? ResolvePersistencePath(IConfiguration configuration)
    {
        var configured = configuration["OAuthServer:EntraTokenPath"];

        if (configured is not null)
        {
            return string.IsNullOrWhiteSpace(configured) ? null : configured;
        }

        if (Directory.Exists("/home"))
        {
            var directory = Path.Combine("/home", "data");
            Directory.CreateDirectory(directory);

            return Path.Combine(directory, "entra-refresh-tokens.json");
        }

        return Path.Combine(AppContext.BaseDirectory, "entra-refresh-tokens.json");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _writeLock.Dispose();
        _tokens.Clear();
        _disposed = true;
    }
}
