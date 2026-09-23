using OneDriveMcp.Core.Models;

namespace OneDriveMcp.Core.Graph;

/// <summary>
/// Typed access to the OneDrive surface of Microsoft Graph.
/// </summary>
/// <remarks>
/// Implementations acquire the caller's Graph token themselves, so tool classes never handle
/// tokens. Failures surface as <see cref="GraphApiException"/> with the status and Graph error
/// code as data rather than as text to be matched.
/// </remarks>
public interface IOneDriveGraphClient
{
    /// <summary>Gets quota and identity for the caller's drive.</summary>
    Task<Models.DriveInfo> GetDriveInfoAsync(CancellationToken cancellationToken);

    /// <summary>Gets metadata for a single item.</summary>
    Task<DriveItem> GetItemAsync(ItemRef reference, CancellationToken cancellationToken);

    /// <summary>Lists the immediate children of a folder.</summary>
    /// <param name="reference">The folder; use <see cref="ItemRef.Root"/> for the drive root.</param>
    /// <param name="pageSize">Items per page, clamped to the configured maximum.</param>
    /// <param name="cursor">Cursor from a previous page, or null to start.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<PagedItems> ListChildrenAsync(
        ItemRef reference,
        int? pageSize,
        string? cursor,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads a file as UTF-8 text, stopping at <paramref name="maxBytes"/>.
    /// </summary>
    Task<FileContent> ReadTextAsync(
        ItemRef reference,
        long maxBytes,
        CancellationToken cancellationToken);

    /// <summary>
    /// Gets the pre-authenticated download URL for a file.
    /// </summary>
    /// <remarks>
    /// The returned URL needs no credentials to fetch, so it is an exfiltration primitive once it
    /// reaches a transcript. Callers must honour the <c>AllowDownloadUrls</c> setting.
    /// </remarks>
    Task<string?> GetDownloadUrlAsync(ItemRef reference, CancellationToken cancellationToken);

    /// <summary>
    /// Uploads content to a path, creating intermediate folders as OneDrive requires.
    /// </summary>
    /// <param name="path">Destination path relative to the drive root.</param>
    /// <param name="content">Content to upload; must be readable and seekable for large uploads.</param>
    /// <param name="length">Total length in bytes.</param>
    /// <param name="conflictBehavior">What to do when the target already exists.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<UploadResult> UploadAsync(
        string path,
        Stream content,
        long length,
        ConflictBehavior conflictBehavior,
        CancellationToken cancellationToken);

    /// <summary>Creates a folder.</summary>
    Task<DriveItem> CreateFolderAsync(
        string? parentPath,
        string name,
        ConflictBehavior conflictBehavior,
        CancellationToken cancellationToken);

    /// <summary>Deletes a file or folder, including everything inside a folder.</summary>
    Task DeleteAsync(ItemRef reference, CancellationToken cancellationToken);

    /// <summary>
    /// Moves and/or renames an item. Graph does both in one PATCH, so they are one operation.
    /// </summary>
    /// <param name="reference">The item to move.</param>
    /// <param name="newParentPath">New parent folder, or null to keep the current one.</param>
    /// <param name="newName">New name, or null to keep the current one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<DriveItem> MoveAsync(
        ItemRef reference,
        string? newParentPath,
        string? newName,
        CancellationToken cancellationToken);

    /// <summary>
    /// Copies an item. Graph performs this asynchronously, so the result may report that the copy
    /// is still running.
    /// </summary>
    Task<CopyResult> CopyAsync(
        ItemRef reference,
        string newParentPath,
        string? newName,
        TimeSpan maxWait,
        CancellationToken cancellationToken);

    /// <summary>Searches the caller's drive.</summary>
    Task<PagedItems> SearchAsync(
        string query,
        int? pageSize,
        string? cursor,
        CancellationToken cancellationToken);

    /// <summary>Lists the caller's recently used items.</summary>
    Task<PagedItems> ListRecentAsync(
        int? pageSize,
        string? cursor,
        CancellationToken cancellationToken);

    /// <summary>Creates a sharing link for an item.</summary>
    /// <param name="reference">The item to share.</param>
    /// <param name="linkType"><c>view</c> or <c>edit</c>.</param>
    /// <param name="scope"><c>organization</c> or <c>anonymous</c>.</param>
    /// <param name="expiresAt">When the link should stop working.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ShareLink> CreateShareLinkAsync(
        ItemRef reference,
        string linkType,
        string scope,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken);

    /// <summary>Lists the permissions on an item.</summary>
    Task<IReadOnlyList<ItemPermission>> ListPermissionsAsync(
        ItemRef reference,
        CancellationToken cancellationToken);

    /// <summary>Revokes a single permission, which is how a sharing link is withdrawn.</summary>
    Task DeletePermissionAsync(
        ItemRef reference,
        string permissionId,
        CancellationToken cancellationToken);
}
