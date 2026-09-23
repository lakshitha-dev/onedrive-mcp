using System.Security.Cryptography;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OneDriveMcp.Server.OAuth.Configuration;

namespace OneDriveMcp.Server.OAuth.Services;

/// <summary>
/// Supplies the RSA key this server signs its own access tokens with.
/// </summary>
/// <remarks>
/// <para>
/// The key is persisted to Key Vault when one is configured, so tokens survive a restart and
/// remain valid across instances. Without persistence every restart silently invalidates every
/// token the server has issued, which is tolerable locally and nowhere else.
/// </para>
/// <para>
/// Persisting means the app <em>writes</em> to Key Vault, so its managed identity needs the
/// Secrets Officer role rather than Secrets User.
/// </para>
/// </remarks>
public sealed class OAuthSigningKeyProvider : IDisposable
{
    private const string SigningKeySecret = "OAuthServer--SigningKey";
    private const string SigningKeyIdSecret = "OAuthServer--SigningKeyId";
    private const string PreviousKeySecret = "OAuthServer--PreviousSigningKey";
    private const string PreviousKeyIdSecret = "OAuthServer--PreviousSigningKeyId";

    private readonly OAuthServerOptions _options;
    private readonly ILogger<OAuthSigningKeyProvider> _logger;
    private readonly List<RSA> _ownedKeys = [];

    private RsaSecurityKey? _currentKey;
    private RsaSecurityKey? _previousKey;
    private bool _disposed;

    /// <summary>Creates the provider. Call <see cref="InitializeAsync"/> before use.</summary>
    public OAuthSigningKeyProvider(
        IOptions<OAuthServerOptions> options,
        ILogger<OAuthSigningKeyProvider> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Credentials used to sign newly issued tokens.</summary>
    public SigningCredentials SigningCredentials =>
        new(Current, SecurityAlgorithms.RsaSha256);

    /// <summary>
    /// Keys accepted when validating a token: the current one, plus the previous one so a
    /// rotation does not invalidate tokens that are still within their lifetime.
    /// </summary>
    public IEnumerable<SecurityKey> ValidationKeys =>
        _previousKey is null ? [Current] : [Current, _previousKey];

    private RsaSecurityKey Current => _currentKey
        ?? throw new InvalidOperationException(
            $"{nameof(OAuthSigningKeyProvider)} was used before {nameof(InitializeAsync)} completed.");

    /// <summary>
    /// Loads the signing key from Key Vault, or creates and stores one.
    /// </summary>
    /// <remarks>
    /// Awaited during startup rather than blocked on inside a DI factory. The implementation this
    /// replaces called <c>.GetAwaiter().GetResult()</c> while building the container, which risks
    /// deadlock and adds a Key Vault round trip to every cold start on the critical path.
    /// </remarks>
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.KeyVaultUri))
        {
            _currentKey = CreateKey(out var keyId);

            _logger.LogWarning(
                "No OAuthServer:KeyVaultUri is configured, so the token signing key is held in " +
                "memory only (kid {KeyId}). Every restart will invalidate all issued tokens.",
                keyId);

            return;
        }

        var client = new SecretClient(new Uri(_options.KeyVaultUri), new DefaultAzureCredential());

        try
        {
            var stored = await TryReadKeyAsync(client, SigningKeySecret, SigningKeyIdSecret, cancellationToken);

            if (stored is not null)
            {
                _currentKey = stored;

                _previousKey = await TryReadKeyAsync(
                    client, PreviousKeySecret, PreviousKeyIdSecret, cancellationToken);

                _logger.LogInformation(
                    "Loaded the OAuth signing key from Key Vault (kid {KeyId})", _currentKey.KeyId);

                return;
            }

            _currentKey = CreateKey(out var newKeyId);
            await StoreKeyAsync(client, _currentKey, cancellationToken);

            _logger.LogInformation(
                "Created and stored a new OAuth signing key in Key Vault (kid {KeyId})", newKeyId);
        }
        catch (Exception exception) when (exception is RequestFailedException or AuthenticationFailedException)
        {
            // Falling back to an in-memory key here would look like a successful start while
            // quietly invalidating every previously issued token, and would diverge per instance.
            // Failing to start is the safer outcome and says plainly what is wrong.
            throw new InvalidOperationException(
                $"Key Vault at '{_options.KeyVaultUri}' is configured for the OAuth signing key " +
                "but could not be reached. Refusing to fall back to an in-memory key. Check the " +
                "vault URI and that the app identity holds the Key Vault Secrets Officer role.",
                exception);
        }
    }

    private async Task<RsaSecurityKey?> TryReadKeyAsync(
        SecretClient client,
        string keySecretName,
        string keyIdSecretName,
        CancellationToken cancellationToken)
    {
        try
        {
            var key = await client.GetSecretAsync(keySecretName, cancellationToken: cancellationToken);
            var keyId = await client.GetSecretAsync(keyIdSecretName, cancellationToken: cancellationToken);

            var rsa = RSA.Create();
            _ownedKeys.Add(rsa);
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(key.Value.Value), out _);

            return new RsaSecurityKey(rsa) { KeyId = keyId.Value.Value };
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            // No key stored yet; the caller creates one.
            return null;
        }
    }

    private async Task StoreKeyAsync(
        SecretClient client,
        RsaSecurityKey key,
        CancellationToken cancellationToken)
    {
        var privateKey = Convert.ToBase64String(key.Rsa.ExportRSAPrivateKey());

        await client.SetSecretAsync(SigningKeySecret, privateKey, cancellationToken);
        await client.SetSecretAsync(SigningKeyIdSecret, key.KeyId, cancellationToken);
    }

    private RsaSecurityKey CreateKey(out string keyId)
    {
        var rsa = RSA.Create(2048);
        _ownedKeys.Add(rsa);

        keyId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));

        return new RsaSecurityKey(rsa) { KeyId = keyId };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (var key in _ownedKeys)
        {
            key.Dispose();
        }

        _ownedKeys.Clear();
        _disposed = true;
    }
}

/// <summary>Initialises the signing key before the server begins accepting requests.</summary>
public sealed class OAuthSigningKeyInitializer(OAuthSigningKeyProvider provider) : IHostedService
{
    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken) =>
        provider.InitializeAsync(cancellationToken);

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
