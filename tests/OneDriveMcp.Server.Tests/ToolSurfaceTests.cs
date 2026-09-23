using System.Text.Json;
using OneDriveMcp.Server.Tests.Fixtures;

namespace OneDriveMcp.Server.Tests;

/// <summary>
/// The published tool surface is a contract with every connected client, and the annotations on
/// it are what let a client prompt before something destructive runs. Both are pinned here.
/// </summary>
[Collection(McpServerCollection.Name)]
public class ToolSurfaceTests(McpServerFixture server)
{
    private readonly McpServerFixture _factory = server;

    /// <summary>Tools that modify or expose data, and must be flagged for the client.</summary>
    public static TheoryData<string> DestructiveTools =>
    [
        "onedrive_upload_file",
        "onedrive_delete_item",
        "onedrive_move_item",
        "onedrive_create_share_link",
        "onedrive_delete_permission"
    ];

    public static TheoryData<string> ReadOnlyTools =>
    [
        "onedrive_list_files",
        "onedrive_get_item",
        "onedrive_read_text_file",
        "onedrive_get_drive_info",
        "onedrive_search",
        "onedrive_list_recent",
        "onedrive_list_permissions"
    ];

    [Fact]
    public async Task AllExpectedToolsArePublished()
    {
        var names = await ToolNamesAsync();

        string[] expected =
        [
            // browse and read
            "onedrive_list_files", "onedrive_get_item", "onedrive_read_text_file",
            "onedrive_get_download_url", "onedrive_get_drive_info",
            // write and organise
            "onedrive_upload_file", "onedrive_create_folder", "onedrive_delete_item",
            "onedrive_move_item", "onedrive_copy_item",
            // search
            "onedrive_search", "onedrive_list_recent",
            // sharing
            "onedrive_create_share_link", "onedrive_list_permissions", "onedrive_delete_permission",
            // diagnostics
            "onedrive_auth_status"
        ];

        Assert.Equal(expected.OrderBy(n => n), names.OrderBy(n => n));
    }

    [Fact]
    public async Task NoSharedWithMeTool()
    {
        // Dropped for v1: Files.ReadWrite only covers the caller's own drive, so listing items
        // from other people's drives would return items this server then cannot open.
        var names = await ToolNamesAsync();

        Assert.DoesNotContain("onedrive_list_shared_with_me", names);
    }

    [Theory]
    [MemberData(nameof(DestructiveTools))]
    public async Task DestructiveToolsAreAnnotatedAsSuch(string toolName)
    {
        // A stateless transport cannot ask the user mid-call, so this annotation is the only
        // signal a client gets that it should confirm first.
        var tool = await FindToolAsync(toolName);

        Assert.True(
            tool.GetProperty("annotations").GetProperty("destructiveHint").GetBoolean(),
            $"{toolName} must be marked destructive.");
    }

    [Theory]
    [MemberData(nameof(ReadOnlyTools))]
    public async Task ReadOnlyToolsAreAnnotatedAsSuch(string toolName)
    {
        var tool = await FindToolAsync(toolName);

        Assert.True(
            tool.GetProperty("annotations").GetProperty("readOnlyHint").GetBoolean(),
            $"{toolName} must be marked read-only.");
    }

    [Fact]
    public async Task EveryToolHasADescriptionAndAnOutputSchema()
    {
        var response = await new McpTestClient(_factory.CreateClient()).ListToolsAsync();

        foreach (var tool in response.GetProperty("result").GetProperty("tools").EnumerateArray())
        {
            var name = tool.GetProperty("name").GetString();

            Assert.True(
                tool.TryGetProperty("description", out var description)
                && !string.IsNullOrWhiteSpace(description.GetString()),
                $"{name} has no description; the model relies on it to choose the tool.");

            Assert.True(
                tool.TryGetProperty("outputSchema", out _),
                $"{name} has no output schema, so its result reaches the client unstructured.");
        }
    }

    [Fact]
    public async Task RequiredParametersAreDeclared()
    {
        var upload = await FindToolAsync("onedrive_upload_file");
        var required = upload.GetProperty("inputSchema").GetProperty("required")
            .EnumerateArray().Select(r => r.GetString()).ToList();

        Assert.Contains("path", required);
        Assert.Contains("content", required);
    }

    // ---------------------------------------------------------------- guards

    [Theory]
    [InlineData("../../secrets.txt")]
    [InlineData("%2E%2E%2Fsecrets.txt")]
    [InlineData("Documents/../../Private/tax.pdf")]
    public async Task PathTraversalIsRejectedBeforeAnyGraphCall(string path)
    {
        // The guard runs while the URL is being built, before a token is even requested. If it
        // ran later, the failure here would be an authentication error instead.
        var (isError, text) = await CallAsync("onedrive_read_text_file", new { path });

        Assert.True(isError);
        Assert.StartsWith("INVALID_PATH:", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DownloadUrlsAreRefusedUnlessEnabled()
    {
        // The URL needs no sign-in, so anyone reading the transcript could fetch the file.
        var (isError, text) = await CallAsync("onedrive_get_download_url", new { path = "a.txt" });

        Assert.True(isError);
        Assert.StartsWith("NOT_PERMITTED:", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnonymousSharingLinksAreRefusedUnlessEnabled()
    {
        var (isError, text) = await CallAsync(
            "onedrive_create_share_link", new { path = "a.txt", scope = "anonymous" });

        Assert.True(isError);
        Assert.StartsWith("NOT_PERMITTED:", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OrganisationScopeIsNotGated()
    {
        // It should fail for want of a Graph token, not because the scope was refused.
        var (isError, text) = await CallAsync(
            "onedrive_create_share_link", new { path = "a.txt", scope = "organization" });

        Assert.True(isError);
        Assert.DoesNotContain("NOT_PERMITTED", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeleteRequiresAnExplicitTarget()
    {
        // Defaulting to the drive root would make an empty argument list catastrophic.
        var (isError, text) = await CallAsync("onedrive_delete_item", new { });

        Assert.True(isError);
        Assert.StartsWith("INVALID_INPUT:", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListFilesDefaultsToTheDriveRoot()
    {
        // Listing, unlike deleting, has a sensible default. It should get as far as needing a
        // token rather than rejecting the empty call.
        var (isError, text) = await CallAsync("onedrive_list_files", new { });

        Assert.True(isError);
        Assert.StartsWith("AUTHENTICATION_REQUIRED:", text, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- error translation

    [Fact]
    public async Task MissingCredentialsProduceAnActionableMessage()
    {
        var (isError, text) = await CallAsync("onedrive_get_drive_info", new { });

        Assert.True(isError);
        Assert.StartsWith("AUTHENTICATION_REQUIRED:", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("conflictBehavior", "nonsense")]
    [InlineData("encoding", "rot13")]
    public async Task InvalidEnumArgumentsNameTheToolParameter(string parameter, string value)
    {
        // The message goes back to the model, which has to correct its own call, so it must name
        // the parameter the caller passed rather than an internal local.
        var arguments = new Dictionary<string, object?>
        {
            ["path"] = "a.txt",
            ["content"] = "hello",
            [parameter] = value
        };

        var (isError, text) = await CallAsync("onedrive_upload_file", arguments);

        Assert.True(isError);
        Assert.StartsWith("INVALID_INPUT:", text, StringComparison.Ordinal);
        Assert.Contains(parameter, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidBase64IsReportedClearly()
    {
        var (isError, text) = await CallAsync("onedrive_upload_file", new
        {
            path = "a.bin",
            content = "!!! not base64 !!!",
            encoding = "base64"
        });

        Assert.True(isError);
        Assert.Contains("base64", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SpecifyingBothPathAndItemIdIsRejected()
    {
        var (isError, text) = await CallAsync(
            "onedrive_get_item", new { path = "a.txt", itemId = "01ABC" });

        Assert.True(isError);
        Assert.Contains("not both", text, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- helpers

    private async Task<List<string?>> ToolNamesAsync()
    {
        var response = await new McpTestClient(_factory.CreateClient()).ListToolsAsync();

        return response.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToList();
    }

    private async Task<JsonElement> FindToolAsync(string toolName)
    {
        var response = await new McpTestClient(_factory.CreateClient()).ListToolsAsync();

        return response.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Single(t => t.GetProperty("name").GetString() == toolName);
    }

    private async Task<(bool IsError, string Text)> CallAsync(string toolName, object arguments)
    {
        var response = await new McpTestClient(_factory.CreateClient())
            .CallToolAsync(toolName, arguments);

        var result = response.GetProperty("result");

        var isError = result.TryGetProperty("isError", out var errorFlag) && errorFlag.GetBoolean();

        var text = result.TryGetProperty("content", out var content)
            && content.GetArrayLength() > 0
            && content[0].TryGetProperty("text", out var textElement)
                ? textElement.GetString() ?? string.Empty
                : string.Empty;

        return (isError, text);
    }
}
