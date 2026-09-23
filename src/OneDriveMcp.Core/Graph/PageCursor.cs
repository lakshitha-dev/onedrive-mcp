using System.Buffers.Text;
using System.Text;

namespace OneDriveMcp.Core.Graph;

/// <summary>
/// Wraps Graph's <c>@odata.nextLink</c> as an opaque pagination cursor.
/// </summary>
/// <remarks>
/// Handing the raw <c>nextLink</c> back to the caller would mean accepting a caller-supplied URL
/// and fetching it with the caller's Graph bearer token attached -- a server-side request forgery
/// primitive that would happily send that token anywhere. The cursor is therefore encoded on the
/// way out and re-validated against the Graph host on the way back in.
/// </remarks>
public static class PageCursor
{
    private const string GraphHost = "graph.microsoft.com";

    /// <summary>Encodes a <c>nextLink</c> as a cursor, or returns null when there is no next page.</summary>
    public static string? Encode(string? nextLink)
    {
        if (string.IsNullOrWhiteSpace(nextLink))
        {
            return null;
        }

        return Base64Url.EncodeToString(Encoding.UTF8.GetBytes(nextLink));
    }

    /// <summary>
    /// Decodes a cursor back into a Graph URL.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// The cursor is malformed, or does not point at Microsoft Graph over HTTPS.
    /// </exception>
    public static string Decode(string cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor))
        {
            throw new ArgumentException("Cursor must not be empty.", nameof(cursor));
        }

        string decoded;

        try
        {
            decoded = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(cursor));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ArgumentException(
                "Cursor is not valid. Pass back the 'nextCursor' value exactly as it was returned.",
                nameof(cursor));
        }

        if (!Uri.TryCreate(decoded, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Cursor does not contain a valid URL.", nameof(cursor));
        }

        // The decoded value is used as a request URL with the caller's Graph token attached, so
        // it must be pinned to Graph itself -- scheme and host both.
        var isGraph = uri.Scheme == Uri.UriSchemeHttps
            && uri.Host.Equals(GraphHost, StringComparison.OrdinalIgnoreCase);

        if (!isGraph)
        {
            throw new ArgumentException(
                "Cursor does not point at Microsoft Graph.", nameof(cursor));
        }

        return uri.AbsoluteUri;
    }
}
