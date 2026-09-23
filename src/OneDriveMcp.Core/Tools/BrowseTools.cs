using System.ComponentModel;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Models;

namespace OneDriveMcp.Core.Tools;

/// <summary>
/// Read-only browsing of the caller's OneDrive.
/// </summary>
/// <remarks>
/// Every tool that acts on an existing item takes either <c>path</c> or <c>item_id</c>. Path is
/// the natural choice when the caller knows where the file lives; ids are what search and recent
/// return, and are the only way to address an item on another drive.
/// </remarks>
[McpServerToolType]
public sealed class BrowseTools(
    IOneDriveGraphClient graphClient,
    IOptions<OneDriveOptions> options)
{
    private readonly IOneDriveGraphClient _graphClient = graphClient
        ?? throw new ArgumentNullException(nameof(graphClient));

    private readonly OneDriveOptions _options = options?.Value
        ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Lists the contents of a folder.</summary>
    [McpServerTool(
        Name = "onedrive_list_files",
        Title = "List OneDrive files and folders",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "List the files and folders directly inside a OneDrive folder. Omit folder_path to list " +
        "the top level of the drive. Results are paged: if nextCursor is returned there are more " +
        "items, and passing it back as cursor fetches the next page.")]
    public Task<PagedItems> ListFilesAsync(
        [Description("Folder path relative to the drive root, such as 'Documents/Reports'. Omit for the top level.")]
        string? folderPath = null,

        [Description("Folder item id, as an alternative to folderPath. Use the id from a search or recent result.")]
        string? folderItemId = null,

        [Description("Maximum items to return in this page.")]
        int? pageSize = null,

        [Description("Cursor from a previous call's nextCursor, to fetch the following page.")]
        string? cursor = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(folderPath, folderItemId, allowRoot: true);

        return _graphClient.ListChildrenAsync(reference, pageSize, cursor, cancellationToken);
    }

    /// <summary>Gets metadata for a single file or folder.</summary>
    [McpServerTool(
        Name = "onedrive_get_item",
        Title = "Get OneDrive item details",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Get details of a single OneDrive file or folder: its id, size, type, last modified time " +
        "and web URL. Specify exactly one of path or itemId.")]
    public Task<DriveItem> GetItemAsync(
        [Description("Path relative to the drive root, such as 'Documents/report.pdf'.")]
        string? path = null,

        [Description("Item id, as an alternative to path.")]
        string? itemId = null,

        [Description("Drive id, only for an item on another user's drive. Requires itemId.")]
        string? driveId = null,

        CancellationToken cancellationToken = default)
    {
        return _graphClient.GetItemAsync(ItemRef.Create(path, itemId, driveId), cancellationToken);
    }

    /// <summary>Reads a text file.</summary>
    [McpServerTool(
        Name = "onedrive_read_text_file",
        Title = "Read a OneDrive text file",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Read the text content of a OneDrive file. Suitable for text, Markdown, CSV, JSON and " +
        "similar formats. Long files are truncated and the result says so. Binary formats such " +
        "as PDF or Office documents will not produce readable text.")]
    public Task<FileContent> ReadTextFileAsync(
        [Description("Path relative to the drive root, such as 'notes/todo.md'.")]
        string? path = null,

        [Description("Item id, as an alternative to path.")]
        string? itemId = null,

        [Description("Drive id, only for an item on another user's drive. Requires itemId.")]
        string? driveId = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(path, itemId, driveId);

        return _graphClient.ReadTextAsync(reference, _options.MaxTextFileReadBytes, cancellationToken);
    }

    /// <summary>Gets a pre-authenticated download URL.</summary>
    /// <remarks>
    /// Disabled by default. The URL Graph returns needs no credentials to fetch, so once it is in
    /// a transcript anyone who reads that transcript can download the file. Deployments that need
    /// it opt in through <c>OneDrive:AllowDownloadUrls</c>.
    /// </remarks>
    [McpServerTool(
        Name = "onedrive_get_download_url",
        Title = "Get a OneDrive download link",
        ReadOnly = true,
        UseStructuredContent = true)]
    [Description(
        "Get a temporary direct download URL for a OneDrive file, for binary files that cannot " +
        "be read as text. The URL requires no sign-in, so treat it as sensitive. This tool is " +
        "disabled unless the server has been configured to allow it.")]
    public async Task<DownloadUrlResult> GetDownloadUrlAsync(
        [Description("Path relative to the drive root.")]
        string? path = null,

        [Description("Item id, as an alternative to path.")]
        string? itemId = null,

        [Description("Drive id, only for an item on another user's drive. Requires itemId.")]
        string? driveId = null,

        CancellationToken cancellationToken = default)
    {
        if (!_options.AllowDownloadUrls)
        {
            throw new InvalidOperationException(
                "Download URLs are disabled on this server. A download URL needs no sign-in to " +
                "use, so it is only issued when 'OneDrive:AllowDownloadUrls' is enabled. Use " +
                "onedrive_read_text_file for text content instead.");
        }

        var reference = ItemRef.Create(path, itemId, driveId);
        var item = await _graphClient.GetItemAsync(reference, cancellationToken);
        var url = await _graphClient.GetDownloadUrlAsync(reference, cancellationToken);

        return new DownloadUrlResult(item, url);
    }

    /// <summary>Gets drive quota and type.</summary>
    [McpServerTool(
        Name = "onedrive_get_drive_info",
        Title = "Get OneDrive storage information",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Get information about the caller's OneDrive: its type, owner, and how much storage is " +
        "used and remaining. Useful before uploading a large file.")]
    public Task<Models.DriveInfo> GetDriveInfoAsync(CancellationToken cancellationToken = default)
    {
        return _graphClient.GetDriveInfoAsync(cancellationToken);
    }
}

/// <summary>
/// A temporary download URL.
/// </summary>
/// <param name="Item">The file the URL points at.</param>
/// <param name="DownloadUrl">
/// Pre-authenticated URL. Anyone holding it can download the file without signing in, and it
/// expires after a short period.
/// </param>
public sealed record DownloadUrlResult(DriveItem Item, string? DownloadUrl);
