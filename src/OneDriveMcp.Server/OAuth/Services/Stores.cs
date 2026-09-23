using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using OneDriveMcp.Server.OAuth.Models;

namespace OneDriveMcp.Server.OAuth.Services;

/// <summary>Stores clients registered through Dynamic Client Registration.</summary>
public interface IOAuthClientStore
{
    /// <summary>Adds a registration.</summary>
    void Add(OAuthClientRegistration registration);

    /// <summary>Finds a registration, or returns null.</summary>
    OAuthClientRegistration? Find(string clientId);

    /// <summary>Every registration, for persistence.</summary>
    IReadOnlyCollection<OAuthClientRegistration> All();

    /// <summary>Replaces the contents, used when restoring persisted state.</summary>
    void Restore(IEnumerable<OAuthClientRegistration> registrations);
}

/// <summary>
/// In-memory client store.
/// </summary>
/// <remarks>
/// Process-local, so a scaled-out deployment needs either session affinity or a shared store.
/// Registrations are written through to disk by <c>OAuthStatePersistence</c> so a restart does
/// not orphan connected clients.
/// </remarks>
public sealed class InMemoryOAuthClientStore : IOAuthClientStore
{
    /// <summary>Cap on stored registrations, so open registration cannot exhaust memory.</summary>
    private const int MaxClients = 10_000;

    private readonly ConcurrentDictionary<string, OAuthClientRegistration> _clients =
        new(StringComparer.Ordinal);

    /// <inheritdoc />
    public void Add(OAuthClientRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        if (_clients.Count >= MaxClients)
        {
            throw new InvalidOperationException(
                "The client registration limit has been reached.");
        }

        _clients[registration.ClientId] = registration;
    }

    /// <inheritdoc />
    public OAuthClientRegistration? Find(string clientId) =>
        string.IsNullOrEmpty(clientId) ? null
            : _clients.TryGetValue(clientId, out var registration) ? registration : null;

    /// <inheritdoc />
    public IReadOnlyCollection<OAuthClientRegistration> All() => _clients.Values.ToArray();

    /// <inheritdoc />
    public void Restore(IEnumerable<OAuthClientRegistration> registrations)
    {
        ArgumentNullException.ThrowIfNull(registrations);

        foreach (var registration in registrations)
        {
            _clients[registration.ClientId] = registration;
        }
    }
}

/// <summary>Tracks access tokens revoked before their natural expiry.</summary>
public interface IAccessTokenDenyList
{
    /// <summary>Revokes a token until the given time.</summary>
    void Revoke(string token, DateTimeOffset expiresAt);

    /// <summary>Whether the token has been revoked.</summary>
    bool IsRevoked(string token);

    /// <summary>
    /// Revokes every access token descended from one authorization grant.
    /// </summary>
    /// <remarks>
    /// Needed because access tokens are self-contained. Marking the refresh tokens revoked stops
    /// new ones being issued but does nothing about one already in an attacker's hands, which
    /// stays valid until it expires -- up to an hour of access after the theft was detected.
    /// </remarks>
    void RevokeFamily(string familyId, DateTimeOffset expiresAt);

    /// <summary>Whether tokens from this grant have been revoked.</summary>
    bool IsFamilyRevoked(string? familyId);

    /// <summary>Current revoked-token entries, for persistence.</summary>
    IReadOnlyDictionary<string, DateTimeOffset> Snapshot();

    /// <summary>Restores persisted revoked-token entries.</summary>
    void Restore(IReadOnlyDictionary<string, DateTimeOffset> entries);

    /// <summary>Current revoked-grant entries, for persistence.</summary>
    IReadOnlyDictionary<string, DateTimeOffset> SnapshotFamilies();

    /// <summary>Restores persisted revoked-grant entries.</summary>
    void RestoreFamilies(IReadOnlyDictionary<string, DateTimeOffset> entries);
}

/// <summary>
/// In-memory deny list for revoked access tokens.
/// </summary>
/// <remarks>
/// A self-issued access token is otherwise valid until it expires, so revocation has to be
/// tracked explicitly. Entries are keyed on a hash rather than the token, so the store never
/// holds a usable credential, and are dropped once the token would have expired anyway.
/// </remarks>
public sealed class InMemoryAccessTokenDenyList : IAccessTokenDenyList
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revoked = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _revokedFamilies = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public void RevokeFamily(string familyId, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(familyId))
        {
            return;
        }

        // Family ids are not secrets -- they identify a grant, not authorise anything -- so
        // unlike the token entries these are stored as they are.
        _revokedFamilies[familyId] = expiresAt;

        PruneExpired();
    }

    /// <inheritdoc />
    public bool IsFamilyRevoked(string? familyId)
    {
        if (string.IsNullOrEmpty(familyId) || !_revokedFamilies.TryGetValue(familyId, out var expiresAt))
        {
            return false;
        }

        if (expiresAt > DateTimeOffset.UtcNow)
        {
            return true;
        }

        // Past this point every token from the grant has expired on its own.
        _revokedFamilies.TryRemove(familyId, out _);

        return false;
    }

    /// <inheritdoc />
    public void Revoke(string token, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(token))
        {
            return;
        }

        _revoked[Hash(token)] = expiresAt;

        PruneExpired();
    }

    /// <inheritdoc />
    public bool IsRevoked(string token)
    {
        if (string.IsNullOrEmpty(token) || !_revoked.TryGetValue(Hash(token), out var expiresAt))
        {
            return false;
        }

        if (expiresAt > DateTimeOffset.UtcNow)
        {
            return true;
        }

        _revoked.TryRemove(Hash(token), out _);

        return false;
    }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, DateTimeOffset> Snapshot() =>
        _revoked.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

    /// <inheritdoc />
    public void Restore(IReadOnlyDictionary<string, DateTimeOffset> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        foreach (var (hash, expiresAt) in entries)
        {
            // Anything already past its expiry is moot: the token it refers to would be rejected
            // on its own lifetime anyway.
            if (expiresAt > DateTimeOffset.UtcNow)
            {
                _revoked[hash] = expiresAt;
            }
        }
    }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, DateTimeOffset> SnapshotFamilies() =>
        _revokedFamilies.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

    /// <inheritdoc />
    public void RestoreFamilies(IReadOnlyDictionary<string, DateTimeOffset> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        foreach (var (familyId, expiresAt) in entries)
        {
            if (expiresAt > DateTimeOffset.UtcNow)
            {
                _revokedFamilies[familyId] = expiresAt;
            }
        }
    }

    private void PruneExpired()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (hash, expiresAt) in _revoked)
        {
            if (expiresAt <= now)
            {
                _revoked.TryRemove(hash, out _);
            }
        }

        foreach (var (familyId, expiresAt) in _revokedFamilies)
        {
            if (expiresAt <= now)
            {
                _revokedFamilies.TryRemove(familyId, out _);
            }
        }
    }

    /// <summary>Hashes the token so a revoked credential is never stored in usable form.</summary>
    private static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
