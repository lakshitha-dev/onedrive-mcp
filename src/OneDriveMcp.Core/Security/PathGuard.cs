using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using OneDriveMcp.Core.Configuration;

namespace OneDriveMcp.Core.Security;

/// <summary>
/// Validates, normalises and escapes OneDrive paths.
/// </summary>
/// <remarks>
/// <para>
/// This carries more weight here than in the gateway this code came from. That server ran against
/// <c>/me/drive/special/approot</c>, so a traversal escaped into an app-private folder at worst.
/// Addressing the user's whole drive means the same bug reaches their real documents.
/// </para>
/// <para>
/// It also fixes a live defect in the original: that implementation validated traversal and then
/// interpolated the raw string straight into the Graph URL. With approot and ASCII filenames that
/// was survivable. On a real drive, <c>#</c> truncates the URL at a fragment, <c>%</c> forms
/// accidental escapes, and <c>?</c> or a crafted segment can append OData query options to the
/// request. Every segment is percent-encoded here before it reaches a URL.
/// </para>
/// </remarks>
public sealed partial class PathGuard(IOptions<OneDriveOptions> options)
{
    private readonly OneDriveOptions _options = options?.Value
        ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Matches a <c>..</c> whole path segment: leading, trailing, or mid-path.</summary>
    [GeneratedRegex(@"(^|[/\\])\.\.([/\\]|$)")]
    private static partial Regex TraversalPattern();

    /// <summary>
    /// Validates a caller-supplied path and returns it normalised: forward slashes, no leading or
    /// trailing separator, no empty segments, and rooted under the configured <c>RootPath</c>.
    /// </summary>
    /// <exception cref="PathTraversalException">The path attempts to escape its root.</exception>
    /// <exception cref="PathDeniedException">The path falls inside a denied prefix.</exception>
    public string Normalize(string? path, string parameterName = "path")
    {
        var relative = NormalizeRelative(path, parameterName);
        var denied = FindDeniedPrefix(relative);

        if (denied is not null)
        {
            throw new PathDeniedException(path ?? string.Empty, denied);
        }

        var root = NormalizeRelative(_options.RootPath, nameof(OneDriveOptions.RootPath));

        if (root.Length == 0)
        {
            return relative;
        }

        return relative.Length == 0 ? root : string.Concat(root, "/", relative);
    }

    /// <summary>
    /// Validates a path and returns it percent-encoded for use inside a Graph
    /// <c>/root:/{path}:</c> address. Returns an empty string for the drive root.
    /// </summary>
    public string ToGraphPath(string? path, string parameterName = "path")
    {
        var normalized = Normalize(path, parameterName);

        if (normalized.Length == 0)
        {
            return string.Empty;
        }

        // Escape each segment separately so the separators survive but every character that would
        // otherwise change the meaning of the URL does not.
        return string.Join('/', normalized.Split('/').Select(Uri.EscapeDataString));
    }

    /// <summary>Validates a single file or folder name, which may not contain a separator.</summary>
    /// <exception cref="ArgumentException">The name is empty or contains a path separator.</exception>
    public string NormalizeName(string? name, string parameterName = "name")
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException($"'{parameterName}' must not be empty.", parameterName);
        }

        var trimmed = name.Trim();

        if (trimmed.Contains('/') || trimmed.Contains('\\'))
        {
            throw new ArgumentException(
                $"'{parameterName}' must be a single name, not a path.", parameterName);
        }

        // Run it through the traversal check anyway, so "." and ".." cannot slip in as a name.
        var normalized = NormalizeRelative(trimmed, parameterName);

        if (normalized.Length == 0)
        {
            throw new ArgumentException($"'{parameterName}' must not be empty.", parameterName);
        }

        return normalized;
    }

    /// <summary>Joins a parent path and a child name into a normalised path.</summary>
    public string Combine(string? parentPath, string name)
    {
        var parent = NormalizeRelative(parentPath, nameof(parentPath));
        var child = NormalizeName(name);

        return parent.Length == 0 ? child : string.Concat(parent, "/", child);
    }

    /// <summary>
    /// Validates and normalises without applying the root prefix or the deny-list, so the same
    /// rules apply to configuration values as to caller input.
    /// </summary>
    private static string NormalizeRelative(string? path, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var decoded = DecodeTraversalEncodings(path).Replace('\\', '/');

        if (decoded.Contains('\0'))
        {
            throw new PathTraversalException(parameterName, path);
        }

        if (TraversalPattern().IsMatch(decoded))
        {
            throw new PathTraversalException(parameterName, path);
        }

        // Dropping empty segments also collapses runs of slashes, so something like "a//../b"
        // cannot be reassembled into a traversal that slipped past the pattern above.
        var segments = decoded
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Where(segment => segment != ".")
            .ToArray();

        foreach (var segment in segments)
        {
            if (segment == "..")
            {
                throw new PathTraversalException(parameterName, path);
            }
        }

        return string.Join('/', segments);
    }

    /// <summary>
    /// Iteratively decodes the encodings that can disguise a traversal, including double and
    /// triple encoding such as <c>%252E%252E%252F</c>.
    /// </summary>
    private static string DecodeTraversalEncodings(string input)
    {
        var result = input;

        for (var i = 0; i < 3; i++)
        {
            var previous = result;

            result = result
                .Replace("%2F", "/", StringComparison.OrdinalIgnoreCase)
                .Replace("%5C", "\\", StringComparison.OrdinalIgnoreCase)
                .Replace("%2E", ".", StringComparison.OrdinalIgnoreCase)
                .Replace("%00", "\0", StringComparison.OrdinalIgnoreCase)
                .Replace("%25", "%", StringComparison.OrdinalIgnoreCase);

            if (string.Equals(result, previous, StringComparison.Ordinal))
            {
                break;
            }
        }

        return result;
    }

    /// <summary>Returns the denied prefix matching this path, or null when it is allowed.</summary>
    private string? FindDeniedPrefix(string relativePath)
    {
        if (_options.DeniedPathPrefixes.Count == 0 || relativePath.Length == 0)
        {
            return null;
        }

        foreach (var configured in _options.DeniedPathPrefixes)
        {
            var prefix = NormalizeRelative(configured, nameof(OneDriveOptions.DeniedPathPrefixes));

            if (prefix.Length == 0)
            {
                continue;
            }

            // Whole-segment match, so a denied "Apps" does not also block "Applications".
            var isMatch = relativePath.Equals(prefix, StringComparison.OrdinalIgnoreCase)
                || relativePath.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase);

            if (isMatch)
            {
                return prefix;
            }
        }

        return null;
    }
}
