using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Models;
using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Core.Graph;

/// <summary>
/// Microsoft Graph client for OneDrive, built on a typed <see cref="HttpClient"/>.
/// </summary>
/// <remarks>
/// Uses raw HTTP rather than the Graph SDK, matching the approach in the gateway this was
/// extracted from: the surface needed here is small, and it keeps the dependency footprint and
/// the error model under our own control.
/// </remarks>
public sealed class OneDriveGraphClient : IOneDriveGraphClient
{
    /// <summary>Named client used for pre-authenticated content URLs, which must carry no token.</summary>
    public const string ContentHttpClientName = "onedrive-content";

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IGraphTokenService _tokenService;
    private readonly GraphAddress _address;
    private readonly PathGuard _pathGuard;
    private readonly OneDriveOptions _options;
    private readonly ILogger<OneDriveGraphClient> _logger;

    /// <summary>Creates a new instance.</summary>
    public OneDriveGraphClient(
        HttpClient httpClient,
        IHttpClientFactory httpClientFactory,
        IGraphTokenService tokenService,
        GraphAddress address,
        PathGuard pathGuard,
        IOptions<OneDriveOptions> options,
        ILogger<OneDriveGraphClient> logger)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
        _address = address ?? throw new ArgumentNullException(nameof(address));
        _pathGuard = pathGuard ?? throw new ArgumentNullException(nameof(pathGuard));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ------------------------------------------------------------------ reads

    /// <inheritdoc />
    public async Task<Models.DriveInfo> GetDriveInfoAsync(CancellationToken cancellationToken)
    {
        using var document = await SendJsonAsync(
            HttpMethod.Get, GraphAddress.Drive(), content: null, cancellationToken);

        return DriveItemMapper.ToDriveInfo(document.RootElement);
    }

    /// <inheritdoc />
    public async Task<DriveItem> GetItemAsync(ItemRef reference, CancellationToken cancellationToken)
    {
        var url = $"{_address.Item(reference)}?$select={DriveItemMapper.ItemSelect}";

        using var document = await SendJsonAsync(HttpMethod.Get, url, content: null, cancellationToken);

        return DriveItemMapper.ToDriveItem(document.RootElement);
    }

    /// <inheritdoc />
    public async Task<PagedItems> ListChildrenAsync(
        ItemRef reference,
        int? pageSize,
        string? cursor,
        CancellationToken cancellationToken)
    {
        var url = cursor is not null
            ? PageCursor.Decode(cursor)
            : $"{_address.Item(reference, "children")}?$select={DriveItemMapper.ItemSelect}&$top={ResolvePageSize(pageSize)}";

        return await GetPageAsync(url, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<PagedItems> SearchAsync(
        string query,
        int? pageSize,
        string? cursor,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            throw new ArgumentException("Search query must not be empty.", nameof(query));
        }

        var url = cursor is not null
            ? PageCursor.Decode(cursor)
            : $"{GraphAddress.Search(query)}?$select={DriveItemMapper.ItemSelect}&$top={ResolvePageSize(pageSize)}";

        return await GetPageAsync(url, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<PagedItems> ListRecentAsync(
        int? pageSize,
        string? cursor,
        CancellationToken cancellationToken)
    {
        var url = cursor is not null
            ? PageCursor.Decode(cursor)
            : $"{GraphAddress.Recent()}?$top={ResolvePageSize(pageSize)}";

        return await GetPageAsync(url, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<FileContent> ReadTextAsync(
        ItemRef reference,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        var item = await GetItemAsync(reference, cancellationToken);

        if (item.IsFolder)
        {
            throw new GraphApiException(
                HttpStatusCode.BadRequest,
                "invalidRequest",
                $"'{item.Name}' is a folder, not a file.");
        }

        var downloadUrl = await GetDownloadUrlAsync(reference, cancellationToken)
            ?? throw new GraphApiException(
                HttpStatusCode.NotFound,
                "itemNotFound",
                $"No downloadable content for '{item.Name}'.");

        using var contentClient = CreateContentClient();
        using var response = await contentClient.GetAsync(
            downloadUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            // This request goes to the content host, not Graph, and carries no token by design.
            // Reporting it like a Graph failure is misleading: a 401 here is not an expired
            // session, and telling the caller to sign in again would not help. The host is named
            // so the failure can be told apart from an authentication problem at a glance.
            var host = new Uri(downloadUrl).Host;

            _logger.LogWarning(
                "Content download from {Host} failed: {Status}. Graph served the file's metadata, " +
                "so the credential is valid and the refusal comes from the content host itself.",
                host, (int)response.StatusCode);

            // A 401 here has a specific and non-obvious cause worth naming. Graph hands out a
            // pre-authenticated URL on a SharePoint host, and tenants can apply Conditional Access
            // or app-enforced restrictions at that layer which Graph itself does not apply. The
            // result is that metadata, uploads, search and sharing all succeed while reading bytes
            // is refused -- for every client, not just this one. Nothing here can work around it,
            // so the message points at the administrator rather than suggesting a retry.
            var explanation = response.StatusCode == HttpStatusCode.Unauthorized
                ? $"The file's content could not be read from {host} (HTTP 401). Everything else " +
                  "about the file worked, so the sign-in is valid. This organisation appears to " +
                  "restrict downloading file content through its SharePoint layer, which no " +
                  "setting on this server can change. A Microsoft 365 administrator would need " +
                  "to check the Conditional Access and app-enforced restriction policies that " +
                  "apply to SharePoint and OneDrive."
                : $"The file's content could not be read from {host} " +
                  $"(HTTP {(int)response.StatusCode}). Graph served the file's details, so this " +
                  "is a problem reaching the content host rather than a sign-in problem.";

            throw new GraphApiException(
                response.StatusCode,
                "contentDownloadFailed",
                explanation,
                ReadRequestId(response));
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);

        // Read one byte past the cap so an exactly-at-limit file is not reported as truncated.
        var buffer = new byte[maxBytes + 1];
        var total = 0;

        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken);

            if (read == 0)
            {
                break;
            }

            total += read;
        }

        var truncated = total > maxBytes;
        var length = truncated ? (int)maxBytes : total;

        return new FileContent(item, Encoding.UTF8.GetString(buffer, 0, length), truncated);
    }

    /// <inheritdoc />
    public async Task<string?> GetDownloadUrlAsync(ItemRef reference, CancellationToken cancellationToken)
    {
        // Ask for the item without $select: @microsoft.graph.downloadUrl is only returned when
        // the projection does not exclude it.
        using var document = await SendJsonAsync(
            HttpMethod.Get, _address.Item(reference), content: null, cancellationToken);

        if (document.RootElement.TryGetProperty("@microsoft.graph.downloadUrl", out var direct) &&
            direct.GetString() is { Length: > 0 } directUrl)
        {
            return GraphUrlGuard.EnsureAllowed(directUrl);
        }

        // Fall back to the redirect on /content. The client is configured not to follow it, so
        // the target can be validated before anything is fetched from it.
        using var request = await CreateRequestAsync(
            HttpMethod.Get, _address.Item(reference, "content"), cancellationToken);

        using var response = await _httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        if (response.StatusCode is HttpStatusCode.Found or HttpStatusCode.Redirect
            or HttpStatusCode.TemporaryRedirect or HttpStatusCode.MovedPermanently)
        {
            var location = response.Headers.Location?.ToString();

            return location is null ? null : GraphUrlGuard.EnsureAllowed(location);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken);
        }

        return null;
    }

    // ------------------------------------------------------------------ writes

    /// <inheritdoc />
    public async Task<UploadResult> UploadAsync(
        string path,
        Stream content,
        long length,
        ConflictBehavior conflictBehavior,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (length > _options.MaxFileSizeBytes)
        {
            throw new ArgumentException(
                $"Content is {length:N0} bytes, which exceeds the {_options.MaxFileSizeBytes:N0} byte limit.",
                nameof(length));
        }

        var normalizedPath = _pathGuard.Normalize(path);

        var item = length > _options.LargeFileThresholdBytes
            ? await UploadLargeAsync(normalizedPath, content, length, conflictBehavior, cancellationToken)
            : await UploadSmallAsync(normalizedPath, content, conflictBehavior, cancellationToken);

        var requestedName = normalizedPath.Split('/')[^1];
        var renamed = !string.Equals(item.Name, requestedName, StringComparison.Ordinal);

        return new UploadResult(
            item,
            Replaced: conflictBehavior == ConflictBehavior.Replace,
            RenamedTo: renamed ? item.Name : null);
    }

    /// <inheritdoc />
    public async Task<DriveItem> CreateFolderAsync(
        string? parentPath,
        string name,
        ConflictBehavior conflictBehavior,
        CancellationToken cancellationToken)
    {
        var folderName = _pathGuard.NormalizeName(name);
        var parent = ItemRef.FromPath(parentPath);

        var body = new Dictionary<string, object?>
        {
            ["name"] = folderName,
            ["folder"] = new Dictionary<string, object?>(),
            ["@microsoft.graph.conflictBehavior"] = ToGraphConflictBehavior(conflictBehavior)
        };

        using var content = JsonContent.Create(body, options: SerializerOptions);

        using var document = await SendJsonAsync(
            HttpMethod.Post, _address.Item(parent, "children"), content, cancellationToken);

        return DriveItemMapper.ToDriveItem(document.RootElement);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(ItemRef reference, CancellationToken cancellationToken)
    {
        using var request = await CreateRequestAsync(
            HttpMethod.Delete, _address.Item(reference), cancellationToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken);
        }
    }

    /// <inheritdoc />
    public async Task<DriveItem> MoveAsync(
        ItemRef reference,
        string? newParentPath,
        string? newName,
        CancellationToken cancellationToken)
    {
        if (newParentPath is null && string.IsNullOrWhiteSpace(newName))
        {
            throw new ArgumentException(
                "Specify a new parent folder, a new name, or both.", nameof(newName));
        }

        var body = new Dictionary<string, object?>();

        if (!string.IsNullOrWhiteSpace(newName))
        {
            body["name"] = _pathGuard.NormalizeName(newName);
        }

        if (newParentPath is not null)
        {
            body["parentReference"] = new Dictionary<string, object?>
            {
                ["path"] = ToParentReferencePath(newParentPath)
            };
        }

        using var content = JsonContent.Create(body, options: SerializerOptions);

        using var document = await SendJsonAsync(
            HttpMethod.Patch, _address.Item(reference), content, cancellationToken);

        return DriveItemMapper.ToDriveItem(document.RootElement);
    }

    /// <inheritdoc />
    public async Task<CopyResult> CopyAsync(
        ItemRef reference,
        string newParentPath,
        string? newName,
        TimeSpan maxWait,
        CancellationToken cancellationToken)
    {
        var body = new Dictionary<string, object?>
        {
            ["parentReference"] = new Dictionary<string, object?>
            {
                ["path"] = ToParentReferencePath(newParentPath)
            }
        };

        if (!string.IsNullOrWhiteSpace(newName))
        {
            body["name"] = _pathGuard.NormalizeName(newName);
        }

        using var request = await CreateRequestAsync(
            HttpMethod.Post, _address.Item(reference, "copy"), cancellationToken);

        request.Content = JsonContent.Create(body, options: SerializerOptions);

        using var response = await _httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken);
        }

        // Graph copies asynchronously: 202 plus a monitor URL rather than the new item.
        var monitorUrl = response.Headers.Location?.ToString();

        if (monitorUrl is null)
        {
            return new CopyResult("inProgress", Item: null, MonitorUrl: null,
                "Copy started. Graph did not return a progress URL.");
        }

        return await PollCopyAsync(monitorUrl, maxWait, cancellationToken);
    }

    // ------------------------------------------------------------------ sharing

    /// <inheritdoc />
    public async Task<ShareLink> CreateShareLinkAsync(
        ItemRef reference,
        string linkType,
        string scope,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken)
    {
        var body = new Dictionary<string, object?>
        {
            ["type"] = linkType,
            ["scope"] = scope
        };

        if (expiresAt.HasValue)
        {
            body["expirationDateTime"] = expiresAt.Value.ToString("o", CultureInfo.InvariantCulture);
        }

        using var content = JsonContent.Create(body, options: SerializerOptions);

        using var document = await SendJsonAsync(
            HttpMethod.Post, _address.Item(reference, "createLink"), content, cancellationToken);

        var link = DriveItemMapper.ToShareLink(document.RootElement);

        _logger.LogInformation(
            "Sharing link created for {Item}: type={LinkType} scope={Scope} expires={Expires}",
            reference, link.LinkType, link.Scope, link.ExpiresAt ?? "never");

        return link;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ItemPermission>> ListPermissionsAsync(
        ItemRef reference,
        CancellationToken cancellationToken)
    {
        using var document = await SendJsonAsync(
            HttpMethod.Get, _address.Item(reference, "permissions"), content: null, cancellationToken);

        var permissions = new List<ItemPermission>();

        if (document.RootElement.TryGetProperty("value", out var value) &&
            value.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in value.EnumerateArray())
            {
                permissions.Add(DriveItemMapper.ToPermission(element));
            }
        }

        return permissions;
    }

    /// <inheritdoc />
    public async Task DeletePermissionAsync(
        ItemRef reference,
        string permissionId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(permissionId))
        {
            throw new ArgumentException("Permission id must not be empty.", nameof(permissionId));
        }

        using var request = await CreateRequestAsync(
            HttpMethod.Delete, _address.Permission(reference, permissionId), cancellationToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken);
        }

        _logger.LogInformation("Permission {PermissionId} revoked on {Item}", permissionId, reference);
    }

    // ------------------------------------------------------------------ upload internals

    private async Task<DriveItem> UploadSmallAsync(
        string path,
        Stream content,
        ConflictBehavior conflictBehavior,
        CancellationToken cancellationToken)
    {
        var url = $"{_address.UploadTarget(path, "content")}" +
                  $"?@microsoft.graph.conflictBehavior={ToGraphConflictBehavior(conflictBehavior)}";

        using var request = await CreateRequestAsync(HttpMethod.Put, url, cancellationToken);

        request.Content = new StreamContent(content);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using var response = await _httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken);
        }

        using var document = await ReadJsonAsync(response, cancellationToken);

        return DriveItemMapper.ToDriveItem(document.RootElement);
    }

    /// <summary>
    /// Uploads via a resumable session.
    /// </summary>
    /// <remarks>
    /// Honours <c>nextExpectedRanges</c> and retries an individual chunk. The implementation this
    /// replaces did neither, so a single failed chunk aborted the entire transfer with no way to
    /// resume -- painful precisely on the large files the session path exists for.
    /// </remarks>
    private async Task<DriveItem> UploadLargeAsync(
        string path,
        Stream content,
        long length,
        ConflictBehavior conflictBehavior,
        CancellationToken cancellationToken)
    {
        const int ChunkSize = 10 * 1024 * 1024;   // a multiple of 320 KiB, as Graph requires
        const int MaxChunkAttempts = 3;

        var sessionBody = new Dictionary<string, object?>
        {
            ["item"] = new Dictionary<string, object?>
            {
                ["name"] = path.Split('/')[^1],
                ["@microsoft.graph.conflictBehavior"] = ToGraphConflictBehavior(conflictBehavior)
            }
        };

        using var sessionContent = JsonContent.Create(sessionBody, options: SerializerOptions);

        using var sessionDocument = await SendJsonAsync(
            HttpMethod.Post,
            _address.UploadTarget(path, "createUploadSession"),
            sessionContent,
            cancellationToken);

        var uploadUrl = sessionDocument.RootElement.TryGetProperty("uploadUrl", out var urlElement)
            ? urlElement.GetString()
            : null;

        if (uploadUrl is null)
        {
            throw new GraphApiException(
                HttpStatusCode.InternalServerError,
                graphErrorCode: null,
                "Graph did not return an upload URL for the resumable session.");
        }

        GraphUrlGuard.EnsureAllowed(uploadUrl);

        // The session URL is itself pre-authenticated. Sending the Graph bearer to it as well
        // would be both unnecessary and a way to leak the token.
        using var uploadClient = CreateContentClient();

        var buffer = new byte[ChunkSize];
        long offset = 0;
        JsonDocument? finalDocument = null;

        try
        {
            while (offset < length)
            {
                var wanted = (int)Math.Min(ChunkSize, length - offset);
                var read = await ReadExactlyAsync(content, buffer, wanted, cancellationToken);

                if (read == 0)
                {
                    break;
                }

                var (document, nextOffset) = await UploadChunkAsync(
                    uploadClient, uploadUrl, buffer, read, offset, length,
                    MaxChunkAttempts, cancellationToken);

                if (document is not null)
                {
                    finalDocument?.Dispose();
                    finalDocument = document;
                }

                if (nextOffset <= offset)
                {
                    // Graph reported a range it already has; without this the loop would spin.
                    offset += read;
                }
                else
                {
                    offset = nextOffset;
                }
            }

            if (finalDocument is null)
            {
                throw new GraphApiException(
                    HttpStatusCode.InternalServerError,
                    graphErrorCode: null,
                    "The upload finished but Graph never returned the completed item.");
            }

            return DriveItemMapper.ToDriveItem(finalDocument.RootElement);
        }
        finally
        {
            finalDocument?.Dispose();
        }
    }

    /// <summary>
    /// Uploads one chunk, retrying transient failures. Returns the completed item once Graph
    /// reports the upload finished, plus the offset it expects next.
    /// </summary>
    private async Task<(JsonDocument? Document, long NextOffset)> UploadChunkAsync(
        HttpClient uploadClient,
        string uploadUrl,
        byte[] buffer,
        int count,
        long offset,
        long totalLength,
        int maxAttempts,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Put, uploadUrl)
            {
                Content = new ByteArrayContent(buffer, 0, count)
            };

            request.Content.Headers.ContentRange =
                new ContentRangeHeaderValue(offset, offset + count - 1, totalLength);
            request.Content.Headers.ContentLength = count;

            HttpResponseMessage? response = null;

            try
            {
                response = await uploadClient.SendAsync(request, cancellationToken);

                if (response.StatusCode is HttpStatusCode.OK or HttpStatusCode.Created)
                {
                    return (await ReadJsonAsync(response, cancellationToken), totalLength);
                }

                if (response.StatusCode == HttpStatusCode.Accepted)
                {
                    using var document = await ReadJsonAsync(response, cancellationToken);

                    return (null, ParseNextExpectedOffset(document.RootElement, offset + count));
                }

                var isTransient = (int)response.StatusCode >= 500
                    || response.StatusCode == HttpStatusCode.TooManyRequests;

                if (!isTransient || attempt >= maxAttempts)
                {
                    throw await CreateExceptionAsync(response, cancellationToken);
                }

                _logger.LogWarning(
                    "Upload chunk at offset {Offset} failed with {Status}; retrying ({Attempt}/{MaxAttempts})",
                    offset, response.StatusCode, attempt, maxAttempts);

                await Task.Delay(RetryDelay(response, attempt), cancellationToken);
            }
            catch (HttpRequestException exception) when (attempt < maxAttempts)
            {
                _logger.LogWarning(
                    exception,
                    "Upload chunk at offset {Offset} failed; retrying ({Attempt}/{MaxAttempts})",
                    offset, attempt, maxAttempts);

                await Task.Delay(RetryDelay(response: null, attempt), cancellationToken);
            }
            finally
            {
                response?.Dispose();
            }
        }
    }

    /// <summary>Reads <c>nextExpectedRanges</c>, falling back to the end of the chunk just sent.</summary>
    private static long ParseNextExpectedOffset(JsonElement root, long fallback)
    {
        if (!root.TryGetProperty("nextExpectedRanges", out var ranges) ||
            ranges.ValueKind != JsonValueKind.Array)
        {
            return fallback;
        }

        foreach (var range in ranges.EnumerateArray())
        {
            // Ranges look like "26214400-" or "26214400-52428799".
            var text = range.GetString();

            if (text is null)
            {
                continue;
            }

            var dashIndex = text.IndexOf('-', StringComparison.Ordinal);
            var startText = dashIndex < 0 ? text : text[..dashIndex];

            if (long.TryParse(startText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var start))
            {
                return start;
            }
        }

        return fallback;
    }

    private static async Task<int> ReadExactlyAsync(
        Stream stream,
        byte[] buffer,
        int count,
        CancellationToken cancellationToken)
    {
        var total = 0;

        while (total < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, count - total), cancellationToken);

            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    // ------------------------------------------------------------------ copy polling

    private async Task<CopyResult> PollCopyAsync(
        string monitorUrl,
        TimeSpan maxWait,
        CancellationToken cancellationToken)
    {
        GraphUrlGuard.EnsureAllowed(monitorUrl);

        using var monitorClient = CreateContentClient();
        var deadline = DateTimeOffset.UtcNow + maxWait;
        var delay = TimeSpan.FromMilliseconds(500);

        while (DateTimeOffset.UtcNow < deadline)
        {
            using var response = await monitorClient.GetAsync(monitorUrl, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                break;
            }

            using var document = await ReadJsonAsync(response, cancellationToken);
            var root = document.RootElement;

            var status = root.TryGetProperty("status", out var statusElement)
                ? statusElement.GetString()
                : null;

            if (string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase))
            {
                var resourceId = root.TryGetProperty("resourceId", out var idElement)
                    ? idElement.GetString()
                    : null;

                if (resourceId is not null)
                {
                    var item = await GetItemAsync(ItemRef.FromId(resourceId), cancellationToken);

                    return new CopyResult("completed", item, MonitorUrl: null, "Copy completed.");
                }

                return new CopyResult("completed", Item: null, MonitorUrl: null, "Copy completed.");
            }

            if (string.Equals(status, "failed", StringComparison.OrdinalIgnoreCase))
            {
                throw new GraphApiException(
                    HttpStatusCode.InternalServerError, "copyFailed", "The copy operation failed.");
            }

            await Task.Delay(delay, cancellationToken);
            delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 2000));
        }

        return new CopyResult(
            "inProgress",
            Item: null,
            MonitorUrl: monitorUrl,
            "Copy is still running. It will finish on its own; check the destination folder shortly.");
    }

    // ------------------------------------------------------------------ plumbing

    private async Task<PagedItems> GetPageAsync(string url, CancellationToken cancellationToken)
    {
        using var document = await SendJsonAsync(HttpMethod.Get, url, content: null, cancellationToken);

        var items = DriveItemMapper.ToDriveItems(document.RootElement);
        var nextCursor = PageCursor.Encode(DriveItemMapper.GetNextLink(document.RootElement));

        return PagedItems.Create(items, nextCursor);
    }

    private async Task<JsonDocument> SendJsonAsync(
        HttpMethod method,
        string url,
        HttpContent? content,
        CancellationToken cancellationToken)
    {
        using var request = await CreateRequestAsync(method, url, cancellationToken);

        if (content is not null)
        {
            request.Content = content;
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw await CreateExceptionAsync(response, cancellationToken);
        }

        return await ReadJsonAsync(response, cancellationToken);
    }

    private async Task<HttpRequestMessage> CreateRequestAsync(
        HttpMethod method,
        string url,
        CancellationToken cancellationToken)
    {
        var token = await _tokenService.GetGraphTokenAsync(cancellationToken);

        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return request;
    }

    private HttpClient CreateContentClient() => _httpClientFactory.CreateClient(ContentHttpClientName);

    private static async Task<JsonDocument> ReadJsonAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        return string.IsNullOrWhiteSpace(body)
            ? JsonDocument.Parse("{}")
            : JsonDocument.Parse(body);
    }

    private async Task<GraphApiException> CreateExceptionAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var requestId = ReadRequestId(response);
        var retryAfter = response.Headers.RetryAfter?.Delta;

        var exception = GraphApiException.FromResponse(
            response.StatusCode, body, requestId, retryAfter);

        _logger.LogWarning(
            "Graph request failed: {Status} {GraphCode} requestId={RequestId}",
            (int)response.StatusCode, exception.GraphErrorCode ?? "(none)", requestId ?? "(none)");

        return exception;
    }

    /// <summary>
    /// Graph's request id. Microsoft support cannot trace a failure without it, so it is pulled
    /// off every error response.
    /// </summary>
    private static string? ReadRequestId(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("request-id", out var requestIds))
        {
            return requestIds.FirstOrDefault();
        }

        return response.Headers.TryGetValues("client-request-id", out var clientIds)
            ? clientIds.FirstOrDefault()
            : null;
    }

    private static TimeSpan RetryDelay(HttpResponseMessage? response, int attempt)
    {
        if (response?.Headers.RetryAfter?.Delta is { } delta)
        {
            return delta;
        }

        return TimeSpan.FromMilliseconds(500 * Math.Pow(2, attempt - 1));
    }

    private int ResolvePageSize(int? requested)
    {
        var size = requested ?? _options.DefaultPageSize;

        return Math.Clamp(size, 1, _options.MaxPageSize);
    }

    private static string ToGraphConflictBehavior(ConflictBehavior behavior) => behavior switch
    {
        ConflictBehavior.Replace => "replace",
        ConflictBehavior.Fail => "fail",
        _ => "rename"
    };

    /// <summary>
    /// Builds a <c>parentReference.path</c> value, which Graph expects in its own
    /// <c>/drive/root:/...</c> form rather than as a plain relative path.
    /// </summary>
    private string ToParentReferencePath(string? path)
    {
        var encoded = _pathGuard.ToGraphPath(path);

        return encoded.Length == 0 ? "/drive/root:" : $"/drive/root:/{encoded}";
    }
}
