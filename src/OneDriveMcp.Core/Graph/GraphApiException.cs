using System.Net;
using System.Text.Json;

namespace OneDriveMcp.Core.Graph;

/// <summary>
/// A failed Microsoft Graph call, carrying the status code and Graph error code as data.
/// </summary>
/// <remarks>
/// The implementation this replaces classified failures by substring-matching exception messages
/// (<c>ex.Message.Contains("itemNotFound")</c>), which silently misfires whenever a filename
/// happens to contain the same text and breaks outright if Graph rewords a message. Everything
/// callers branch on is a typed property here.
/// </remarks>
public sealed class GraphApiException : Exception
{
    /// <summary>Creates a new instance.</summary>
    public GraphApiException(
        HttpStatusCode statusCode,
        string? graphErrorCode,
        string message,
        string? requestId = null,
        TimeSpan? retryAfter = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        GraphErrorCode = graphErrorCode;
        RequestId = requestId;
        RetryAfter = retryAfter;
    }

    /// <summary>The HTTP status returned by Graph.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>The Graph error code, such as <c>itemNotFound</c> or <c>nameAlreadyExists</c>.</summary>
    public string? GraphErrorCode { get; }

    /// <summary>
    /// Graph's request id. Without this Microsoft support cannot trace a failure, so it is
    /// logged on every error.
    /// </summary>
    public string? RequestId { get; }

    /// <summary>The <c>Retry-After</c> value, when Graph supplied one.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>The item, folder or drive named in the request does not exist.</summary>
    public bool IsNotFound =>
        StatusCode == HttpStatusCode.NotFound
        || string.Equals(GraphErrorCode, "itemNotFound", StringComparison.OrdinalIgnoreCase);

    /// <summary>An item already exists at the target path.</summary>
    public bool IsConflict =>
        StatusCode == HttpStatusCode.Conflict
        || string.Equals(GraphErrorCode, "nameAlreadyExists", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The token is valid but lacks the required permission. Usually a missing or unconsented
    /// Graph scope rather than anything wrong with the request.
    /// </summary>
    public bool IsPermissionDenied =>
        StatusCode == HttpStatusCode.Forbidden
        || string.Equals(GraphErrorCode, "accessDenied", StringComparison.OrdinalIgnoreCase);

    /// <summary>The credential was rejected, so the caller needs to authenticate again.</summary>
    public bool IsUnauthorized => StatusCode == HttpStatusCode.Unauthorized;

    /// <summary>Graph is throttling or briefly unavailable; the request may be retried.</summary>
    public bool IsThrottled =>
        StatusCode == HttpStatusCode.TooManyRequests
        || StatusCode == HttpStatusCode.ServiceUnavailable;

    /// <summary>The caller is over their OneDrive storage quota.</summary>
    public bool IsQuotaExceeded =>
        StatusCode == HttpStatusCode.InsufficientStorage
        || string.Equals(GraphErrorCode, "quotaLimitReached", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Builds an exception from a Graph error response, extracting the error code, message and
    /// request id from the body when it is well-formed.
    /// </summary>
    public static GraphApiException FromResponse(
        HttpStatusCode statusCode,
        string? responseBody,
        string? requestId = null,
        TimeSpan? retryAfter = null)
    {
        var (code, message) = ParseErrorBody(responseBody);

        var description = message ?? $"Microsoft Graph returned {(int)statusCode} {statusCode}.";

        return new GraphApiException(statusCode, code, description, requestId, retryAfter);
    }

    /// <summary>
    /// Pulls <c>error.code</c>, <c>error.message</c> and the inner request id out of a Graph
    /// error body. Returns nulls rather than throwing when the body is missing or not JSON --
    /// a parse failure here must not mask the original error.
    /// </summary>
    private static (string? Code, string? Message) ParseErrorBody(string? responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return (null, null);
        }

        try
        {
            using var document = JsonDocument.Parse(responseBody);

            if (!document.RootElement.TryGetProperty("error", out var error))
            {
                return (null, null);
            }

            var code = error.TryGetProperty("code", out var codeElement)
                ? codeElement.GetString()
                : null;

            var message = error.TryGetProperty("message", out var messageElement)
                ? messageElement.GetString()
                : null;

            return (code, message);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }
}
