namespace OneDriveMcp.Core.Models;

/// <summary>How Graph should behave when an upload target already exists.</summary>
public enum ConflictBehavior
{
    /// <summary>Keep both, giving the new file a numbered name. The default: it never loses data.</summary>
    Rename = 0,

    /// <summary>Overwrite the existing file.</summary>
    Replace = 1,

    /// <summary>Fail the upload.</summary>
    Fail = 2
}

/// <summary>
/// Outcome of an upload.
/// </summary>
/// <param name="Item">The resulting file.</param>
/// <param name="Replaced">True when an existing file was overwritten.</param>
/// <param name="RenamedTo">
/// Set when the conflict behaviour was <see cref="ConflictBehavior.Rename"/> and Graph chose a
/// different name than requested.
/// </param>
public sealed record UploadResult(DriveItem Item, bool Replaced, string? RenamedTo);

/// <summary>
/// Text content read from a file.
/// </summary>
/// <param name="Item">Metadata for the file that was read.</param>
/// <param name="Content">The decoded text.</param>
/// <param name="Truncated">
/// True when the file was longer than the configured read limit and <see cref="Content"/> holds
/// only the beginning of it.
/// </param>
public sealed record FileContent(DriveItem Item, string Content, bool Truncated);

/// <summary>
/// A sharing link.
/// </summary>
/// <param name="PermissionId">
/// Id of the permission the link created. Pass it to the delete-permission tool to revoke access.
/// </param>
/// <param name="Url">The shareable URL.</param>
/// <param name="LinkType">Access granted, either <c>view</c> or <c>edit</c>.</param>
/// <param name="Scope">Audience: <c>organization</c> or <c>anonymous</c>.</param>
/// <param name="ExpiresAt">When the link stops working, in ISO 8601.</param>
public sealed record ShareLink(
    string? PermissionId,
    string? Url,
    string? LinkType,
    string? Scope,
    string? ExpiresAt);

/// <summary>
/// A permission entry on an item.
/// </summary>
/// <param name="Id">Permission id, used to revoke it.</param>
/// <param name="Roles">Roles granted, such as <c>read</c> or <c>write</c>.</param>
/// <param name="GrantedTo">Who holds the permission, when it is a person rather than a link.</param>
/// <param name="LinkType">Link type, when the permission is a sharing link.</param>
/// <param name="LinkScope">Link audience, when the permission is a sharing link.</param>
/// <param name="LinkUrl">Link URL, when the permission is a sharing link.</param>
/// <param name="ExpiresAt">Expiry, in ISO 8601, when one is set.</param>
/// <param name="IsInherited">True when the permission comes from an ancestor folder.</param>
public sealed record ItemPermission(
    string Id,
    IReadOnlyList<string> Roles,
    string? GrantedTo,
    string? LinkType,
    string? LinkScope,
    string? LinkUrl,
    string? ExpiresAt,
    bool IsInherited);

/// <summary>
/// Outcome of a delete.
/// </summary>
/// <param name="Deleted">Always true; a failure surfaces as an error instead.</param>
/// <param name="Item">How the deleted item was addressed.</param>
/// <param name="Message">Human-readable confirmation.</param>
public sealed record DeleteResult(bool Deleted, string Item, string Message);

/// <summary>
/// Outcome of a copy, which Graph performs asynchronously.
/// </summary>
/// <param name="Status">
/// <c>completed</c> when the copy finished within the wait window, otherwise <c>inProgress</c>.
/// </param>
/// <param name="Item">The new item, when the copy completed in time.</param>
/// <param name="MonitorUrl">
/// Graph's progress URL, returned when the copy is still running so the caller can decide whether
/// to keep waiting.
/// </param>
/// <param name="Message">Human-readable status.</param>
public sealed record CopyResult(
    string Status,
    DriveItem? Item,
    string? MonitorUrl,
    string Message);
