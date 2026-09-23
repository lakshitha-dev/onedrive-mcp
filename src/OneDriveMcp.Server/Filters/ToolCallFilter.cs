using System.Diagnostics;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Server.Filters;

/// <summary>
/// Cross-cutting behaviour for every tool call: correlation, timing, concurrency limiting and
/// turning exceptions into results a model can act on.
/// </summary>
/// <remarks>
/// The gateway this was extracted from did all of this inline in a single 190-line handler
/// lambda, which is why its tool methods were hard to read. Putting it in one filter keeps the
/// tool methods to nothing but Graph logic.
/// </remarks>
public sealed class ToolCallFilter : IDisposable
{
    private readonly SemaphoreSlim _concurrencyLimiter;
    private readonly ILogger<ToolCallFilter> _logger;

    /// <summary>Creates the filter.</summary>
    public ToolCallFilter(IOptions<OneDriveOptions> options, ILogger<ToolCallFilter> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _concurrencyLimiter = new SemaphoreSlim(options.Value.MaxConcurrentRequests);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>How long to wait for a concurrency slot before giving up.</summary>
    private static readonly TimeSpan SlotWaitTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Wraps a tool invocation.</summary>
    public async ValueTask<CallToolResult> InvokeAsync(
        RequestContext<CallToolRequestParams> context,
        McpRequestHandler<CallToolRequestParams, CallToolResult> next,
        CancellationToken cancellationToken)
    {
        var toolName = context.Params?.Name ?? "(unknown)";
        var correlationId = Activity.Current?.Id ?? Guid.NewGuid().ToString("N")[..8];

        if (!await _concurrencyLimiter.WaitAsync(SlotWaitTimeout, cancellationToken))
        {
            _logger.LogWarning(
                "[{CorrelationId}] {Tool} rejected: no concurrency slot within {Timeout}",
                correlationId, toolName, SlotWaitTimeout);

            return Error(
                "The server is handling too many requests right now. Try again in a moment.");
        }

        var stopwatch = Stopwatch.StartNew();

        try
        {
            var result = await next(context, cancellationToken);

            _logger.LogInformation(
                "[{CorrelationId}] {Tool} completed in {ElapsedMs}ms",
                correlationId, toolName, stopwatch.ElapsedMilliseconds);

            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller went away. Let this propagate rather than reporting it as a tool failure.
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(
                exception,
                "[{CorrelationId}] {Tool} failed after {ElapsedMs}ms",
                correlationId, toolName, stopwatch.ElapsedMilliseconds);

            return Error(Describe(exception, correlationId));
        }
        finally
        {
            _concurrencyLimiter.Release();
        }
    }

    /// <summary>
    /// Turns an exception into a message the model can act on.
    /// </summary>
    /// <remarks>
    /// Recoverable problems get specific, actionable text. Anything unrecognised is deliberately
    /// generic and carries only the correlation id, so internal detail does not leak to a caller
    /// while still being traceable in the logs.
    /// </remarks>
    private static string Describe(Exception exception, string correlationId) => exception switch
    {
        AuthenticationRequiredException authentication =>
            $"AUTHENTICATION_REQUIRED: {authentication.Message}",

        TokenExchangeFailedException tokenExchange =>
            $"AUTHENTICATION_ERROR: Could not obtain access to OneDrive. {tokenExchange.Message}",

        PathTraversalException =>
            "INVALID_PATH: The path is not allowed. Use a path relative to the OneDrive root, " +
            "without '..' segments.",

        PathDeniedException denied =>
            $"ACCESS_DENIED: {denied.Message}",

        GraphApiException graph => DescribeGraphFailure(graph),

        // Tool input validation. The message names the parameter and what it expects, so the
        // model can correct the call itself.
        ArgumentException argument => $"INVALID_INPUT: {argument.Message}",

        // Used by the tools for a configuration-gated capability, where the message explains
        // which setting governs it.
        InvalidOperationException invalid => $"NOT_PERMITTED: {invalid.Message}",

        TimeoutException =>
            "TIMEOUT: OneDrive did not respond in time. Try again.",

        _ => $"INTERNAL_ERROR: The operation failed unexpectedly (reference {correlationId})."
    };

    private static string DescribeGraphFailure(GraphApiException exception)
    {
        if (exception.IsNotFound)
        {
            return "NOT_FOUND: No such file or folder in OneDrive. Check the path, or use " +
                   "onedrive_search to locate it.";
        }

        if (exception.IsConflict)
        {
            return "CONFLICT: An item with that name already exists. Choose another name, or " +
                   "set conflictBehavior to 'rename' or 'replace'.";
        }

        // Checked before the status-code cases below: a 401 from the content host is not a
        // session expiry, and sending the caller off to re-authenticate would waste their time.
        if (string.Equals(exception.GraphErrorCode, "contentDownloadFailed", StringComparison.Ordinal))
        {
            return $"CONTENT_UNAVAILABLE: {exception.Message}";
        }

        if (exception.IsUnauthorized)
        {
            return "SESSION_EXPIRED: Access to OneDrive has expired. Sign in again.";
        }

        if (exception.IsPermissionDenied)
        {
            return "PERMISSION_DENIED: OneDrive refused this operation. The signed-in account " +
                   "may not have permission for this item, or the Files.ReadWrite scope may not " +
                   "have been consented.";
        }

        if (exception.IsQuotaExceeded)
        {
            return "QUOTA_EXCEEDED: The OneDrive account is out of storage. Free up space and " +
                   "try again.";
        }

        if (exception.IsThrottled)
        {
            var retry = exception.RetryAfter is { } delay
                ? $" Retry in about {(int)delay.TotalSeconds} seconds."
                : " Retry shortly.";

            return $"RATE_LIMITED: OneDrive is throttling requests.{retry}";
        }

        var reference = exception.RequestId is null ? string.Empty : $" (request {exception.RequestId})";

        return $"ONEDRIVE_ERROR: {exception.Message}{reference}";
    }

    private static CallToolResult Error(string message) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = message }]
    };

    /// <inheritdoc />
    public void Dispose() => _concurrencyLimiter.Dispose();
}
