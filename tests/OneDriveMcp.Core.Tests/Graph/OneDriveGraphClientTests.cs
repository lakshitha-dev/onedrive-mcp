using System.Net;
using System.Text;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Models;
using OneDriveMcp.Core.Tests.Fakes;

namespace OneDriveMcp.Core.Tests.Graph;

public class OneDriveGraphClientTests
{
    private const string FileJson = """
        {
          "id": "01ABCDEF",
          "name": "report.pdf",
          "size": 1024,
          "lastModifiedDateTime": "2026-09-01T10:00:00Z",
          "file": { "mimeType": "application/pdf" },
          "webUrl": "https://contoso-my.sharepoint.com/personal/x/report.pdf",
          "parentReference": { "driveId": "drive-1", "path": "/drive/root:/Documents" }
        }
        """;

    // ---------------------------------------------------------------- addressing

    [Fact]
    public async Task GetItem_ByPath_UsesTheColonAddressingForm()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        await harness.Client.GetItemAsync(ItemRef.FromPath("Documents/report.pdf"), default);

        Assert.StartsWith(
            "https://graph.microsoft.com/v1.0/me/drive/root:/Documents/report.pdf?$select=",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetItem_ById_UsesTheItemsForm()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        await harness.Client.GetItemAsync(ItemRef.FromId("01ABCDEF"), default);

        Assert.StartsWith(
            "https://graph.microsoft.com/v1.0/me/drive/items/01ABCDEF?$select=",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetItem_OnAnotherDrive_UsesTheDrivesForm()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        await harness.Client.GetItemAsync(ItemRef.FromId("item-9", "drive-7"), default);

        Assert.StartsWith(
            "https://graph.microsoft.com/v1.0/drives/drive-7/items/item-9?$select=",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListChildren_OfRoot_OmitsThePathSegment()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""{"value":[]}""");

        await harness.Client.ListChildrenAsync(ItemRef.Root, null, null, default);

        Assert.Contains(
            "/v1.0/me/drive/root/children?",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListChildren_OfFolder_AddsTheClosingColonBeforeTheSubResource()
    {
        // Item metadata is /root:/{path} with no trailing colon, but a sub-resource needs one.
        // Getting it wrong yields a puzzling 400 rather than an obvious failure.
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""{"value":[]}""");

        await harness.Client.ListChildrenAsync(ItemRef.FromPath("Documents"), null, null, default);

        Assert.Contains(
            "/v1.0/me/drive/root:/Documents:/children?",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetItem_EscapesMetacharactersInThePath()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        await harness.Client.GetItemAsync(ItemRef.FromPath("Q1 #1/50% done.txt"), default);

        var url = harness.Graph.SingleRequest.Url;

        Assert.Contains("/root:/Q1%20%231/50%25%20done.txt", url, StringComparison.Ordinal);

        // A raw '#' would truncate the URL at a fragment and the request would hit the folder.
        Assert.DoesNotContain('#', url);
    }

    // ---------------------------------------------------------------- error mapping

    [Fact]
    public async Task NotFound_MapsToATypedException()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueError(HttpStatusCode.NotFound, "itemNotFound", "Item does not exist");

        var exception = await Assert.ThrowsAsync<GraphApiException>(
            () => harness.Client.GetItemAsync(ItemRef.FromPath("missing.txt"), default));

        Assert.True(exception.IsNotFound);
        Assert.Equal("itemNotFound", exception.GraphErrorCode);
        Assert.Equal("Item does not exist", exception.Message);
    }

    [Fact]
    public async Task Throttling_CarriesTheRetryAfterValue()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueError(
            HttpStatusCode.TooManyRequests, "activityLimitReached",
            retryAfter: TimeSpan.FromSeconds(30));

        var exception = await Assert.ThrowsAsync<GraphApiException>(
            () => harness.Client.GetItemAsync(ItemRef.FromPath("a.txt"), default));

        Assert.True(exception.IsThrottled);
        Assert.Equal(TimeSpan.FromSeconds(30), exception.RetryAfter);
    }

    [Fact]
    public async Task Errors_CaptureTheGraphRequestId()
    {
        // Microsoft support cannot trace a failure without this.
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueError(
            HttpStatusCode.InternalServerError, "generalException", requestId: "req-abc-123");

        var exception = await Assert.ThrowsAsync<GraphApiException>(
            () => harness.Client.GetItemAsync(ItemRef.FromPath("a.txt"), default));

        Assert.Equal("req-abc-123", exception.RequestId);
    }

    [Fact]
    public async Task MalformedErrorBody_DoesNotMaskTheStatusCode()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueContent("<html>gateway timeout</html>", HttpStatusCode.GatewayTimeout);

        var exception = await Assert.ThrowsAsync<GraphApiException>(
            () => harness.Client.GetItemAsync(ItemRef.FromPath("a.txt"), default));

        Assert.Equal(HttpStatusCode.GatewayTimeout, exception.StatusCode);
        Assert.Null(exception.GraphErrorCode);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "accessDenied")]
    [InlineData(HttpStatusCode.Conflict, "nameAlreadyExists")]
    [InlineData(HttpStatusCode.InsufficientStorage, "quotaLimitReached")]
    public async Task ErrorClassification_IsByStatusAndCodeNotMessageText(
        HttpStatusCode status,
        string graphCode)
    {
        // The implementation this replaces branched on ex.Message.Contains("itemNotFound"), which
        // misfires whenever a filename happens to contain the same text.
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueError(status, graphCode, message: "a file named itemNotFound.txt");

        var exception = await Assert.ThrowsAsync<GraphApiException>(
            () => harness.Client.GetItemAsync(ItemRef.FromPath("itemNotFound.txt"), default));

        Assert.False(exception.IsNotFound);
        Assert.Equal(graphCode, exception.GraphErrorCode);
    }

    // ---------------------------------------------------------------- downloads

    [Fact]
    public async Task GetDownloadUrl_PrefersTheMetadataUrl()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {
              "id": "1", "name": "a.txt",
              "@microsoft.graph.downloadUrl": "https://contoso-my.sharepoint.com/download/a.txt"
            }
            """);

        var url = await harness.Client.GetDownloadUrlAsync(ItemRef.FromPath("a.txt"), default);

        Assert.Equal("https://contoso-my.sharepoint.com/download/a.txt", url);
    }

    [Fact]
    public async Task GetDownloadUrl_FollowsTheContentRedirectWhenMetadataHasNoUrl()
    {
        using var harness = new GraphClientHarness();
        harness.Graph
            .EnqueueJson("""{"id":"1","name":"a.txt"}""")
            .EnqueueRedirect("https://abc.files.1drv.com/content/a.txt");

        var url = await harness.Client.GetDownloadUrlAsync(ItemRef.FromPath("a.txt"), default);

        Assert.Equal("https://abc.files.1drv.com/content/a.txt", url);
    }

    [Theory]
    [InlineData("https://evil.example.com/steal")]
    [InlineData("http://contoso-my.sharepoint.com/insecure")]          // not HTTPS
    [InlineData("https://sharepoint.com.evil.example.com/steal")]      // suffix confusion
    [InlineData("https://evil-sharepoint.com/steal")]
    public async Task GetDownloadUrl_RefusesUrlsOutsideTheAllowList(string location)
    {
        // Following an arbitrary redirect would turn any Graph response into a server-side
        // request forgery primitive.
        using var harness = new GraphClientHarness();
        harness.Graph
            .EnqueueJson("""{"id":"1","name":"a.txt"}""")
            .EnqueueRedirect(location);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Client.GetDownloadUrlAsync(ItemRef.FromPath("a.txt"), default));
    }

    [Fact]
    public async Task ReadText_FetchesContentWithoutTheBearerToken()
    {
        // The download URL is already pre-authenticated. Forwarding the Graph bearer to that host
        // would hand over the caller's access to their entire drive.
        using var harness = new GraphClientHarness();
        harness.Graph
            .EnqueueJson(FileJson)
            .EnqueueJson("""
                {
                  "id": "1", "name": "report.pdf",
                  "@microsoft.graph.downloadUrl": "https://contoso-my.sharepoint.com/d/report.pdf"
                }
                """);
        harness.Content.EnqueueContent("hello world");

        var result = await harness.Client.ReadTextAsync(ItemRef.FromPath("report.pdf"), 1024, default);

        Assert.Equal("hello world", result.Content);
        Assert.False(result.Truncated);
        Assert.Null(harness.Content.SingleRequest.Authorization);
        Assert.All(harness.Graph.Requests, r => Assert.Equal("Bearer test-token", r.Authorization));
    }

    [Fact]
    public async Task ReadText_TruncatesAtTheConfiguredLimit()
    {
        using var harness = new GraphClientHarness();
        harness.Graph
            .EnqueueJson(FileJson)
            .EnqueueJson("""
                {
                  "id": "1", "name": "report.pdf",
                  "@microsoft.graph.downloadUrl": "https://contoso-my.sharepoint.com/d/report.pdf"
                }
                """);
        harness.Content.EnqueueContent(new string('x', 500));

        var result = await harness.Client.ReadTextAsync(ItemRef.FromPath("report.pdf"), 100, default);

        Assert.True(result.Truncated);
        Assert.Equal(100, result.Content.Length);
    }

    [Fact]
    public async Task ReadText_RejectsAFolder()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {"id":"1","name":"Documents","folder":{"childCount":3},
             "parentReference":{"path":"/drive/root:"}}
            """);

        var exception = await Assert.ThrowsAsync<GraphApiException>(
            () => harness.Client.ReadTextAsync(ItemRef.FromPath("Documents"), 1024, default));

        Assert.Contains("is a folder", exception.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- uploads

    [Fact]
    public async Task Upload_SmallFile_UsesASinglePutWithTheConflictBehaviour()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        using var content = new MemoryStream(Encoding.UTF8.GetBytes("hello"));
        await harness.Client.UploadAsync("Documents/a.txt", content, 5, ConflictBehavior.Fail, default);

        var request = harness.Graph.SingleRequest;

        Assert.Equal(HttpMethod.Put, request.Method);
        Assert.Contains(
            "/root:/Documents/a.txt:/content?@microsoft.graph.conflictBehavior=fail",
            request.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Upload_DefaultsToRenameSoNothingIsSilentlyOverwritten()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        using var content = new MemoryStream(Encoding.UTF8.GetBytes("hello"));
        await harness.Client.UploadAsync("a.txt", content, 5, ConflictBehavior.Rename, default);

        Assert.Contains(
            "conflictBehavior=rename",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Upload_AboveThreshold_UsesAResumableSession()
    {
        using var harness = new GraphClientHarness(options =>
        {
            options.LargeFileThresholdBytes = 10;
            options.MaxFileSizeBytes = 1_000_000;
        });

        harness.Graph.EnqueueJson(
            """{"uploadUrl":"https://abc.up.svc.ms/session/1"}""");
        harness.Content.EnqueueJson(FileJson, HttpStatusCode.Created);

        using var content = new MemoryStream(new byte[64]);
        await harness.Client.UploadAsync("big.bin", content, 64, ConflictBehavior.Replace, default);

        Assert.Contains(
            "createUploadSession",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"@microsoft.graph.conflictBehavior\":\"replace\"",
            harness.Graph.SingleRequest.Body,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Upload_ChunkRequests_CarryNoAuthorizationHeader()
    {
        // The session upload URL is pre-authenticated; attaching the Graph bearer to it is both
        // unnecessary and a way to leak the token to whatever host Graph named.
        using var harness = new GraphClientHarness(options =>
        {
            options.LargeFileThresholdBytes = 10;
            options.MaxFileSizeBytes = 1_000_000;
        });

        harness.Graph.EnqueueJson("""{"uploadUrl":"https://abc.up.svc.ms/session/1"}""");
        harness.Content.EnqueueJson(FileJson, HttpStatusCode.Created);

        using var content = new MemoryStream(new byte[64]);
        await harness.Client.UploadAsync("big.bin", content, 64, ConflictBehavior.Rename, default);

        Assert.All(harness.Content.Requests, r => Assert.Null(r.Authorization));
        Assert.Equal("bytes 0-63/64", harness.Content.SingleRequest.ContentRange);
    }

    [Fact]
    public async Task Upload_HonoursNextExpectedRanges()
    {
        // Graph can accept less than was sent. Resuming from the offset it reports -- rather than
        // assuming the chunk landed whole -- is what the previous implementation never did.
        using var harness = new GraphClientHarness(options =>
        {
            options.LargeFileThresholdBytes = 10;
            options.MaxFileSizeBytes = 100_000_000;
        });

        harness.Graph.EnqueueJson("""{"uploadUrl":"https://abc.up.svc.ms/session/1"}""");

        var totalLength = 12L * 1024 * 1024;   // two 10 MiB chunks
        harness.Content
            .EnqueueUploadAccepted(nextExpectedOffset: 5 * 1024 * 1024)
            .EnqueueJson(FileJson, HttpStatusCode.Created);

        using var content = new MemoryStream(new byte[totalLength]);
        await harness.Client.UploadAsync("big.bin", content, totalLength, ConflictBehavior.Rename, default);

        Assert.Equal(2, harness.Content.Requests.Count);

        // The second chunk must start where Graph said it expects data, not at 10 MiB.
        Assert.StartsWith(
            "bytes 5242880-",
            harness.Content.Requests[1].ContentRange!,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Upload_RetriesATransientChunkFailure()
    {
        using var harness = new GraphClientHarness(options =>
        {
            options.LargeFileThresholdBytes = 10;
            options.MaxFileSizeBytes = 1_000_000;
        });

        harness.Graph.EnqueueJson("""{"uploadUrl":"https://abc.up.svc.ms/session/1"}""");
        harness.Content
            .EnqueueError(HttpStatusCode.ServiceUnavailable, "serviceNotAvailable",
                retryAfter: TimeSpan.Zero)
            .EnqueueJson(FileJson, HttpStatusCode.Created);

        using var content = new MemoryStream(new byte[64]);
        var result = await harness.Client.UploadAsync(
            "big.bin", content, 64, ConflictBehavior.Rename, default);

        Assert.Equal(2, harness.Content.Requests.Count);
        Assert.Equal("report.pdf", result.Item.Name);
    }

    [Fact]
    public async Task Upload_RejectsAFileOverTheConfiguredMaximum()
    {
        using var harness = new GraphClientHarness(options => options.MaxFileSizeBytes = 100);

        using var content = new MemoryStream(new byte[10]);

        await Assert.ThrowsAsync<ArgumentException>(
            () => harness.Client.UploadAsync("a.bin", content, 200, ConflictBehavior.Rename, default));

        Assert.Empty(harness.Graph.Requests);
    }

    // ---------------------------------------------------------------- move, delete, share

    [Fact]
    public async Task Move_SendsNameAndParentInOnePatch()
    {
        // Graph does move and rename in a single PATCH, which is why they are one tool.
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        await harness.Client.MoveAsync(
            ItemRef.FromPath("a.txt"), "Archive/2026", "b.txt", default);

        var request = harness.Graph.SingleRequest;

        Assert.Equal(HttpMethod.Patch, request.Method);
        Assert.Contains("\"name\":\"b.txt\"", request.Body, StringComparison.Ordinal);
        Assert.Contains("/drive/root:/Archive/2026", request.Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Move_RequiresSomethingToChange()
    {
        using var harness = new GraphClientHarness();

        await Assert.ThrowsAsync<ArgumentException>(
            () => harness.Client.MoveAsync(ItemRef.FromPath("a.txt"), null, null, default));
    }

    [Fact]
    public async Task Delete_IssuesADeleteToTheItemAddress()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueNoContent();

        await harness.Client.DeleteAsync(ItemRef.FromId("01ABC"), default);

        Assert.Equal(HttpMethod.Delete, harness.Graph.SingleRequest.Method);
        Assert.EndsWith("/me/drive/items/01ABC", harness.Graph.SingleRequest.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateShareLink_PostsTypeScopeAndExpiry()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {"id":"perm-1","link":{"type":"view","scope":"organization",
             "webUrl":"https://contoso-my.sharepoint.com/:b:/g/abc"}}
            """);

        var expiry = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        var link = await harness.Client.CreateShareLinkAsync(
            ItemRef.FromPath("a.txt"), "view", "organization", expiry, default);

        var request = harness.Graph.SingleRequest;

        Assert.Contains("createLink", request.Url, StringComparison.Ordinal);
        Assert.Contains("\"scope\":\"organization\"", request.Body, StringComparison.Ordinal);
        Assert.Contains("expirationDateTime", request.Body, StringComparison.Ordinal);
        Assert.Equal("perm-1", link.PermissionId);
    }

    [Fact]
    public async Task DeletePermission_TargetsThePermissionSubResource()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueNoContent();

        await harness.Client.DeletePermissionAsync(ItemRef.FromId("01ABC"), "perm-1", default);

        Assert.EndsWith(
            "/me/drive/items/01ABC/permissions/perm-1",
            harness.Graph.SingleRequest.Url,
            StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- search and paging

    [Fact]
    public async Task Search_EscapesApostrophesInTheQuery()
    {
        // An unescaped apostrophe terminates the OData literal and the remainder is parsed as
        // OData. "O'Brien" is an ordinary name, not a crafted payload.
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""{"value":[]}""");

        await harness.Client.SearchAsync("O'Brien", null, null, default);

        Assert.Contains("search(q='O''Brien')", harness.Graph.SingleRequest.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Search_RejectsAnEmptyQuery()
    {
        using var harness = new GraphClientHarness();

        await Assert.ThrowsAsync<ArgumentException>(
            () => harness.Client.SearchAsync("   ", null, null, default));
    }

    [Fact]
    public async Task ListChildren_ReturnsAnOpaqueCursorForTheNextPage()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/drive/root/children?$skiptoken=abc"}
            """);

        var page = await harness.Client.ListChildrenAsync(ItemRef.Root, null, null, default);

        Assert.NotNull(page.NextCursor);

        // The raw nextLink must not leak out: it comes back as a URL the server would fetch.
        Assert.DoesNotContain("graph.microsoft.com", page.NextCursor, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListChildren_FollowsACursorBackToTheSameUrl()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {"value":[],"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/drive/root/children?$skiptoken=abc"}
            """);

        var first = await harness.Client.ListChildrenAsync(ItemRef.Root, null, null, default);

        harness.Graph.EnqueueJson("""{"value":[]}""");
        await harness.Client.ListChildrenAsync(ItemRef.Root, null, first.NextCursor, default);

        Assert.Equal(
            "https://graph.microsoft.com/v1.0/me/drive/root/children?$skiptoken=abc",
            harness.Graph.Requests[1].Url);
    }

    [Fact]
    public async Task ListChildren_ClampsThePageSizeToTheConfiguredMaximum()
    {
        using var harness = new GraphClientHarness(options => options.MaxPageSize = 25);
        harness.Graph.EnqueueJson("""{"value":[]}""");

        await harness.Client.ListChildrenAsync(ItemRef.Root, 5000, null, default);

        Assert.Contains("$top=25", harness.Graph.SingleRequest.Url, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- mapping

    [Fact]
    public async Task GetItem_MapsGraphJsonOntoTheResultModel()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson(FileJson);

        var item = await harness.Client.GetItemAsync(ItemRef.FromPath("Documents/report.pdf"), default);

        Assert.Equal("01ABCDEF", item.Id);
        Assert.Equal("report.pdf", item.Name);
        Assert.Equal("Documents/report.pdf", item.Path);
        Assert.False(item.IsFolder);
        Assert.Equal(1024, item.Size);
        Assert.Equal("application/pdf", item.MimeType);
    }

    [Fact]
    public async Task GetItem_RebuildsThePathFromTheParentReference()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {"id":"1","name":"a b.txt","size":1,
             "parentReference":{"driveId":"d","path":"/drive/root:/My%20Folder/Sub"}}
            """);

        var item = await harness.Client.GetItemAsync(ItemRef.FromId("1"), default);

        // Graph percent-encodes this path; it must be decoded so it round-trips through our
        // own escaping rather than being double-encoded on the next call.
        Assert.Equal("My Folder/Sub/a b.txt", item.Path);
    }

    [Fact]
    public async Task GetDriveInfo_MapsQuota()
    {
        using var harness = new GraphClientHarness();
        harness.Graph.EnqueueJson("""
            {"id":"drive-1","driveType":"business",
             "owner":{"user":{"displayName":"Ada Lovelace"}},
             "quota":{"total":1000,"used":400,"remaining":600},
             "webUrl":"https://contoso-my.sharepoint.com/personal/ada"}
            """);

        var info = await harness.Client.GetDriveInfoAsync(default);

        Assert.Equal("business", info.DriveType);
        Assert.Equal("Ada Lovelace", info.OwnerDisplayName);
        Assert.Equal(600, info.RemainingBytes);
    }
}
