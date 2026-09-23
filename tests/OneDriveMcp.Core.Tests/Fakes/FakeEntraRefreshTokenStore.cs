using System.Collections.Concurrent;
using OneDriveMcp.Core.Auth;

namespace OneDriveMcp.Core.Tests.Fakes;

/// <summary>
/// In-memory refresh token store for tests, which also records what was written.
/// </summary>
/// <remarks>
/// The rotation behaviour matters: Entra replaces the refresh token on each use, so the store has
/// to be updated or the next call presents one that has already been spent. Tracking writes makes
/// that observable.
/// </remarks>
internal sealed class FakeEntraRefreshTokenStore : IEntraRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, string> _tokens = new(StringComparer.Ordinal);

    /// <summary>Every token written, in order, as (subject, token).</summary>
    public List<(string SubjectId, string RefreshToken)> Writes { get; } = [];

    /// <summary>Subjects whose token has been removed.</summary>
    public List<string> Removals { get; } = [];

    /// <summary>Seeds delegated access for a user.</summary>
    public FakeEntraRefreshTokenStore Seed(string subjectId, string refreshToken)
    {
        _tokens[subjectId] = refreshToken;
        return this;
    }

    /// <summary>The token currently stored for a user, or null.</summary>
    public string? Current(string subjectId) =>
        _tokens.TryGetValue(subjectId, out var token) ? token : null;

    /// <inheritdoc />
    public Task<string?> GetAsync(string subjectId, CancellationToken cancellationToken) =>
        Task.FromResult(Current(subjectId));

    /// <inheritdoc />
    public Task SetAsync(string subjectId, string refreshToken, CancellationToken cancellationToken)
    {
        _tokens[subjectId] = refreshToken;
        Writes.Add((subjectId, refreshToken));

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string subjectId, CancellationToken cancellationToken)
    {
        _tokens.TryRemove(subjectId, out _);
        Removals.Add(subjectId);

        return Task.CompletedTask;
    }
}
