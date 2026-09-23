using System.ComponentModel;
using System.Text;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Models;

namespace OneDriveMcp.Core.Tools;

/// <summary>
/// Tools that create, change or remove items.
/// </summary>
/// <remarks>
/// Each of these is marked <c>Destructive</c> so clients can prompt before running it. That
/// matters more here than in the app-folder design this came from: these act on the caller's
/// real documents, and a stateless transport cannot ask the user mid-call.
/// </remarks>
[McpServerToolType]
public sealed class WriteTools(
    IOneDriveGraphClient graphClient,
    IOptions<OneDriveOptions> options)
{
    private readonly IOneDriveGraphClient _graphClient = graphClient
        ?? throw new ArgumentNullException(nameof(graphClient));

    private readonly OneDriveOptions _options = options?.Value
        ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Uploads a file.</summary>
    [McpServerTool(
        Name = "onedrive_upload_file",
        Title = "Upload a file to OneDrive",
        Destructive = true,
        UseStructuredContent = true)]
    [Description(
        "Create or update a file in OneDrive. Parent folders are created automatically. " +
        "By default a name clash keeps both files by renaming the new one, so nothing is " +
        "overwritten unless conflictBehavior is set to 'replace'. For binary content set " +
        "encoding to 'base64'.")]
    public async Task<UploadResult> UploadFileAsync(
        [Description("Destination path relative to the drive root, such as 'Documents/notes.md'.")]
        string path,

        [Description("File content. Plain text unless encoding is 'base64'.")]
        string content,

        [Description("Either 'text' for text content or 'base64' for binary content. Defaults to 'text'.")]
        string? encoding = null,

        [Description("On a name clash: 'rename' keeps both (default), 'replace' overwrites, 'fail' aborts.")]
        string? conflictBehavior = null,

        CancellationToken cancellationToken = default)
    {
        var bytes = DecodeContent(content, encoding);
        var behavior = ParseConflictBehavior(conflictBehavior);

        using var stream = new MemoryStream(bytes, writable: false);

        return await _graphClient.UploadAsync(
            path, stream, bytes.Length, behavior, cancellationToken);
    }

    /// <summary>Creates a folder.</summary>
    [McpServerTool(
        Name = "onedrive_create_folder",
        Title = "Create a OneDrive folder",
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Create a folder in OneDrive. Set conflictBehavior to 'fail' to get an error when the " +
        "folder already exists; by default an existing folder of the same name is left alone " +
        "and a new one is created with a distinct name.")]
    public Task<DriveItem> CreateFolderAsync(
        [Description("Name of the new folder.")]
        string name,

        [Description("Parent folder path relative to the drive root. Omit to create at the top level.")]
        string? parentPath = null,

        [Description("On a name clash: 'rename' (default), 'replace', or 'fail'.")]
        string? conflictBehavior = null,

        CancellationToken cancellationToken = default)
    {
        return _graphClient.CreateFolderAsync(
            parentPath, name, ParseConflictBehavior(conflictBehavior), cancellationToken);
    }

    /// <summary>Deletes a file or folder.</summary>
    [McpServerTool(
        Name = "onedrive_delete_item",
        Title = "Delete a OneDrive file or folder",
        Destructive = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Move a OneDrive file or folder to the recycle bin. Deleting a folder also removes " +
        "everything inside it. Specify exactly one of path or itemId.")]
    public async Task<DeleteResult> DeleteItemAsync(
        [Description("Path relative to the drive root.")]
        string? path = null,

        [Description("Item id, as an alternative to path.")]
        string? itemId = null,

        [Description("Drive id, only for an item on another user's drive. Requires itemId.")]
        string? driveId = null,

        CancellationToken cancellationToken = default)
    {
        // No allowRoot here: deleting the entire drive root must never be a default.
        var reference = ItemRef.Create(path, itemId, driveId);

        await _graphClient.DeleteAsync(reference, cancellationToken);

        return new DeleteResult(
            Deleted: true,
            Item: reference.ToString(),
            Message: $"Moved '{reference}' to the recycle bin.");
    }

    /// <summary>Moves and/or renames an item.</summary>
    [McpServerTool(
        Name = "onedrive_move_item",
        Title = "Move or rename a OneDrive item",
        Destructive = true,
        UseStructuredContent = true)]
    [Description(
        "Move a OneDrive file or folder to a different folder, rename it, or both in one step. " +
        "Provide at least one of newParentPath or newName.")]
    public Task<DriveItem> MoveItemAsync(
        [Description("Path of the item to move, relative to the drive root.")]
        string? path = null,

        [Description("Item id of the item to move, as an alternative to path.")]
        string? itemId = null,

        [Description("Destination folder path. Omit to keep the item where it is and only rename it.")]
        string? newParentPath = null,

        [Description("New name for the item. Omit to keep the current name.")]
        string? newName = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(path, itemId);

        return _graphClient.MoveAsync(reference, newParentPath, newName, cancellationToken);
    }

    /// <summary>Copies an item.</summary>
    [McpServerTool(
        Name = "onedrive_copy_item",
        Title = "Copy a OneDrive item",
        UseStructuredContent = true)]
    [Description(
        "Copy a OneDrive file or folder to another folder. OneDrive performs copies in the " +
        "background, so for a large item the result may report status 'inProgress' -- the copy " +
        "still completes on its own.")]
    public Task<CopyResult> CopyItemAsync(
        [Description("Path of the item to copy, relative to the drive root.")]
        string? path = null,

        [Description("Item id of the item to copy, as an alternative to path.")]
        string? itemId = null,

        [Description("Destination folder path relative to the drive root. Omit for the top level.")]
        string? newParentPath = null,

        [Description("Name for the copy. Omit to keep the original name.")]
        string? newName = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(path, itemId);

        return _graphClient.CopyAsync(
            reference,
            newParentPath ?? string.Empty,
            newName,
            // Wait briefly so small copies return the finished item, but never block a tool call
            // on a large one.
            maxWait: TimeSpan.FromSeconds(10),
            cancellationToken);
    }

    /// <summary>Decodes tool content into bytes, enforcing the size caps.</summary>
    private byte[] DecodeContent(string content, string? encoding)
    {
        ArgumentNullException.ThrowIfNull(content);

        var isBase64 = string.Equals(encoding, "base64", StringComparison.OrdinalIgnoreCase);

        if (!isBase64)
        {
            if (encoding is not null &&
                !string.Equals(encoding, "text", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "encoding must be either 'text' or 'base64'.", nameof(encoding));
            }

            return Encoding.UTF8.GetBytes(content);
        }

        byte[] bytes;

        try
        {
            bytes = Convert.FromBase64String(content);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "content is not valid base64. Either fix the encoding or send it as text.",
                nameof(content),
                exception);
        }

        // Base64 inflates by a third and the payload exists twice in memory: once in the JSON-RPC
        // buffer and once decoded. The cap is deliberately well below the general file limit.
        if (bytes.Length > _options.MaxBase64UploadBytes)
        {
            throw new ArgumentException(
                $"Decoded content is {bytes.Length:N0} bytes, over the " +
                $"{_options.MaxBase64UploadBytes:N0} byte limit for base64 uploads. " +
                "Large files should be added to OneDrive directly rather than through this tool.",
                nameof(content));
        }

        return bytes;
    }

    private static ConflictBehavior ParseConflictBehavior(string? value) => value?.ToLowerInvariant() switch
    {
        null or "" or "rename" => ConflictBehavior.Rename,
        "replace" => ConflictBehavior.Replace,
        "fail" => ConflictBehavior.Fail,
        // Named for the tool parameter, not the local: the message goes back to the model, which
        // has to correct its own call.
        _ => throw new ArgumentException(
            "conflictBehavior must be 'rename', 'replace' or 'fail'.", "conflictBehavior")
    };
}
