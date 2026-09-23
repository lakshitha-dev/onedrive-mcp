using System.Net;
using System.Text;

namespace OneDriveMcp.Core.Tests.Fakes;

/// <summary>A request captured by <see cref="StubHttpMessageHandler"/>.</summary>
/// <param name="Method">HTTP method.</param>
/// <param name="Url">Absolute request URL.</param>
/// <param name="Authorization">The Authorization header value, or null when absent.</param>
/// <param name="ContentRange">The Content-Range header value, or null when absent.</param>
/// <param name="Body">The request body as text.</param>
public sealed record CapturedRequest(
    HttpMethod Method,
    string Url,
    string? Authorization,
    string? ContentRange,
    string Body);

/// <summary>
/// Records outgoing requests and replays queued responses.
/// </summary>
/// <remarks>
/// Hand-written rather than mocked: the assertions here are about exact URLs, headers and the
/// order of calls, which reads far more clearly against a real recorded list than against
/// expectations set on a protected method.
/// </remarks>
internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();

    /// <summary>Every request the handler saw, in order.</summary>
    public List<CapturedRequest> Requests { get; } = [];

    /// <summary>The single request the handler saw. Fails when there was not exactly one.</summary>
    public CapturedRequest SingleRequest => Requests.Count == 1
        ? Requests[0]
        : throw new InvalidOperationException(
            $"Expected exactly one request but saw {Requests.Count}.");

    /// <summary>Queues a JSON response.</summary>
    public StubHttpMessageHandler EnqueueJson(string json, HttpStatusCode status = HttpStatusCode.OK)
    {
        _responses.Enqueue(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });

        return this;
    }

    /// <summary>Queues a raw body response, for file content.</summary>
    public StubHttpMessageHandler EnqueueContent(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        _responses.Enqueue(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/plain")
        });

        return this;
    }

    /// <summary>Queues a Graph error response.</summary>
    public StubHttpMessageHandler EnqueueError(
        HttpStatusCode status,
        string graphCode,
        string message = "error",
        string? requestId = null,
        TimeSpan? retryAfter = null)
    {
        var json = $"{{\"error\":{{\"code\":\"{graphCode}\",\"message\":\"{message}\"}}}}";

        _responses.Enqueue(_ =>
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };

            if (requestId is not null)
            {
                response.Headers.TryAddWithoutValidation("request-id", requestId);
            }

            if (retryAfter is not null)
            {
                response.Headers.RetryAfter =
                    new System.Net.Http.Headers.RetryConditionHeaderValue(retryAfter.Value);
            }

            return response;
        });

        return this;
    }

    /// <summary>Queues a redirect, as Graph returns for a content download.</summary>
    public StubHttpMessageHandler EnqueueRedirect(string location)
    {
        _responses.Enqueue(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = new Uri(location);
            return response;
        });

        return this;
    }

    /// <summary>Queues an empty success, as Graph returns for a delete.</summary>
    public StubHttpMessageHandler EnqueueNoContent()
    {
        _responses.Enqueue(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        return this;
    }

    /// <summary>Queues a 202 with <c>nextExpectedRanges</c>, as an upload session returns mid-transfer.</summary>
    public StubHttpMessageHandler EnqueueUploadAccepted(long nextExpectedOffset)
    {
        return EnqueueJson(
            $"{{\"nextExpectedRanges\":[\"{nextExpectedOffset}-\"]}}",
            HttpStatusCode.Accepted);
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);

        Requests.Add(new CapturedRequest(
            request.Method,
            request.RequestUri!.AbsoluteUri,
            request.Headers.Authorization?.ToString(),
            request.Content?.Headers.ContentRange?.ToString(),
            body));

        if (_responses.Count == 0)
        {
            throw new InvalidOperationException(
                $"No response queued for {request.Method} {request.RequestUri}.");
        }

        return _responses.Dequeue()(request);
    }
}
