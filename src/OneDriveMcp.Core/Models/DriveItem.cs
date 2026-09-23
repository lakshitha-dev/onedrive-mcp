namespace OneDriveMcp.Core.Models;

/// <summary>
/// A file or folder in OneDrive, flattened from the Graph <c>driveItem</c> resource.
/// </summary>
/// <param name="Id">Graph item id. Pass this back as <c>item_id</c> to act on the item.</param>
/// <param name="Name">File or folder name.</param>
/// <param name="Path">
/// Path relative to the drive root. Null for items on another drive, which can only be addressed
/// by <see cref="Id"/> plus <see cref="DriveId"/>.
/// </param>
/// <param name="IsFolder">True for a folder, false for a file.</param>
/// <param name="Size">Size in bytes; for a folder, the total size of its contents.</param>
/// <param name="LastModified">When the item was last changed, in ISO 8601.</param>
/// <param name="MimeType">Content type, for files only.</param>
/// <param name="WebUrl">Browser URL for the item.</param>
/// <param name="ChildCount">Number of immediate children, for folders only.</param>
/// <param name="DriveId">
/// Set only when the item lives on another user's drive, in which case both this and
/// <see cref="Id"/> are needed to address it.
/// </param>
public sealed record DriveItem(
    string Id,
    string Name,
    string? Path,
    bool IsFolder,
    long Size,
    string? LastModified,
    string? MimeType,
    string? WebUrl,
    int? ChildCount = null,
    string? DriveId = null);

/// <summary>
/// One page of results.
/// </summary>
/// <param name="Items">The items on this page.</param>
/// <param name="NextCursor">
/// Opaque cursor for the next page, or null when this is the last one. Pass it back as
/// <c>cursor</c> to continue. Listing a real drive can return far more than fits in one response,
/// so every list and search tool pages.
/// </param>
/// <param name="Count">Number of items on this page.</param>
public sealed record PagedItems(
    IReadOnlyList<DriveItem> Items,
    string? NextCursor,
    int Count)
{
    /// <summary>Creates a page, deriving the count from the items.</summary>
    public static PagedItems Create(IReadOnlyList<DriveItem> items, string? nextCursor) =>
        new(items, nextCursor, items.Count);
}

/// <summary>
/// Quota and identity for the caller's drive.
/// </summary>
/// <param name="DriveId">The drive's id.</param>
/// <param name="DriveType">Drive type, such as <c>personal</c> or <c>business</c>.</param>
/// <param name="OwnerDisplayName">Display name of the drive's owner.</param>
/// <param name="TotalBytes">Total storage.</param>
/// <param name="UsedBytes">Storage used.</param>
/// <param name="RemainingBytes">Storage remaining.</param>
/// <param name="WebUrl">Browser URL for the drive.</param>
public sealed record DriveInfo(
    string? DriveId,
    string? DriveType,
    string? OwnerDisplayName,
    long? TotalBytes,
    long? UsedBytes,
    long? RemainingBytes,
    string? WebUrl);
