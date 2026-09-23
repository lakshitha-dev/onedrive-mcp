using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace OneDriveMcp.Server.OAuth.Services;

/// <summary>
/// The authorization request parameters held server-side while the user considers consent.
/// </summary>
/// <param name="SubjectId">The authenticated user the consent belongs to.</param>
/// <param name="ClientId">Client requesting authorization.</param>
/// <param name="RedirectUri">Where the code will be returned.</param>
/// <param name="CodeChallenge">PKCE challenge.</param>
/// <param name="Scope">Scope being consented to.</param>
/// <param name="State">Client state, echoed back on redirect.</param>
/// <param name="Email">User's email, for the access token.</param>
public sealed record ConsentSession(
    string SubjectId,
    string ClientId,
    string RedirectUri,
    string CodeChallenge,
    string? Scope,
    string? State,
    string? Email);

/// <summary>
/// Holds consent sessions, keyed by a single-use CSRF token.
/// </summary>
/// <remarks>
/// <para>
/// The consent form carries only the CSRF token. Every security-relevant parameter — the redirect
/// URI above all — is read back from here rather than from the posted form, so tampering with the
/// form cannot redirect the resulting authorization code somewhere else.
/// </para>
/// <para>
/// Backed by an in-process cache, which is one of the reasons this server is single-instance for
/// now. A scaled-out deployment needs a shared cache or session affinity.
/// </para>
/// </remarks>
public sealed class ConsentSessionStore(IMemoryCache cache)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    private readonly IMemoryCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));

    /// <summary>
    /// Tokens this instance has issued, for diagnosis only.
    /// </summary>
    /// <remarks>
    /// Sessions live in memory, so a token posted back to a process that never issued it -- after
    /// a restart, or against a different instance -- looks identical to one that expired. Keeping
    /// the identifiers apart from the cache tells those two cases apart, which the failure reason
    /// alone cannot.
    /// </remarks>
    private readonly HashSet<string> _issued = [];
    private readonly Lock _issuedGate = new();

    /// <summary>Short, non-secret identifier for a token, safe to log.</summary>
    private static string Fingerprint(string token) =>
        token.Length <= 8 ? "(short)" : token[..8];

    /// <summary>Stores a session and returns its single-use token.</summary>
    public string Create(ConsentSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        var token = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        _cache.Set(CacheKey(token), session, Lifetime);

        lock (_issuedGate)
        {
            _issued.Add(Fingerprint(token));
        }

        return token;
    }

    /// <summary>The short identifier of a token, for logging.</summary>
    public static string Describe(string? token) =>
        string.IsNullOrWhiteSpace(token) ? "(none)" : Fingerprint(token);

    /// <summary>Whether this instance ever issued the given token.</summary>
    public bool WasIssuedHere(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        lock (_issuedGate)
        {
            return _issued.Contains(Fingerprint(token));
        }
    }

    /// <summary>How many consent tokens this instance has issued since it started.</summary>
    public int IssuedCount
    {
        get
        {
            lock (_issuedGate)
            {
                return _issued.Count;
            }
        }
    }

    /// <summary>Why a consent session could not be consumed.</summary>
    public enum ConsentFailure
    {
        /// <summary>Consumed successfully.</summary>
        None = 0,

        /// <summary>The form carried no token.</summary>
        MissingToken,

        /// <summary>No session for that token: expired, already used, or never issued.</summary>
        UnknownToken,

        /// <summary>The session belongs to a different signed-in user.</summary>
        SubjectMismatch
    }

    /// <summary>
    /// Consumes a session token, returning the stored request.
    /// </summary>
    /// <param name="token">The CSRF token from the form.</param>
    /// <param name="subjectId">The user posting the form.</param>
    /// <param name="failure">Why it could not be consumed, when it could not.</param>
    /// <remarks>
    /// The caller is told apart the three reasons because they need very different responses:
    /// an expired session is a retry, whereas a subject mismatch is somebody posting another
    /// user's form. A single null told nobody which had happened.
    /// </remarks>
    public ConsentSession? Consume(string? token, string subjectId, out ConsentFailure failure)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            failure = ConsentFailure.MissingToken;
            return null;
        }

        var key = CacheKey(token);

        if (!_cache.TryGetValue<ConsentSession>(key, out var session) || session is null)
        {
            failure = ConsentFailure.UnknownToken;
            return null;
        }

        // Single use: remove before returning, so a replayed form cannot mint a second code.
        _cache.Remove(key);

        // The session belongs to whoever was signed in when it was created. Without this check a
        // token captured from one user could be posted by another.
        if (!string.Equals(session.SubjectId, subjectId, StringComparison.Ordinal))
        {
            failure = ConsentFailure.SubjectMismatch;
            return null;
        }

        failure = ConsentFailure.None;
        return session;
    }

    private static string CacheKey(string token) => $"oauth-consent:{token}";
}
