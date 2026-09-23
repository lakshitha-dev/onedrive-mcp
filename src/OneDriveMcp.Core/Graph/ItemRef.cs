namespace OneDriveMcp.Core.Graph;

/// <summary>
/// Identifies a drive item either by path or by id.
/// </summary>
/// <remarks>
/// Path-only addressing is not sufficient once the server leaves the app folder. Search results,
/// recent files and shared items come back as ids, sometimes on another drive, and several Graph
/// operations (permissions in particular) have no path form at all. Every tool that acts on an
/// existing item therefore accepts both and funnels them through here.
/// </remarks>
public sealed record ItemRef
{
    private ItemRef(string? path, string? itemId, string? driveId)
    {
        Path = path;
        ItemId = itemId;
        DriveId = driveId;
    }

    /// <summary>Path relative to the drive root, when addressed by path.</summary>
    public string? Path { get; }

    /// <summary>Graph item id, when addressed by id.</summary>
    public string? ItemId { get; }

    /// <summary>
    /// Drive containing the item. Only set for items on another user's drive, which is how
    /// shared items are addressed; null means the caller's own drive.
    /// </summary>
    public string? DriveId { get; }

    /// <summary>True when this reference is by id rather than by path.</summary>
    public bool IsById => ItemId is not null;

    /// <summary>The drive root.</summary>
    public static ItemRef Root { get; } = new(path: null, itemId: null, driveId: null);

    /// <summary>References an item by path relative to the drive root.</summary>
    public static ItemRef FromPath(string? path) => new(path, itemId: null, driveId: null);

    /// <summary>References an item by id, optionally on another drive.</summary>
    /// <exception cref="ArgumentException">The id is empty.</exception>
    public static ItemRef FromId(string itemId, string? driveId = null)
    {
        if (string.IsNullOrWhiteSpace(itemId))
        {
            throw new ArgumentException("Item id must not be empty.", nameof(itemId));
        }

        return new ItemRef(path: null, itemId.Trim(), string.IsNullOrWhiteSpace(driveId) ? null : driveId.Trim());
    }

    /// <summary>
    /// Builds a reference from the optional <c>path</c> / <c>itemId</c> pair that tools accept,
    /// requiring exactly one of them.
    /// </summary>
    /// <param name="path">Path relative to the drive root.</param>
    /// <param name="itemId">Graph item id.</param>
    /// <param name="driveId">Drive id, for an item on another user's drive.</param>
    /// <param name="allowRoot">
    /// When true, omitting both means the drive root. When false -- the usual case for an
    /// operation that must act on a specific item -- omitting both is an error.
    /// </param>
    /// <exception cref="ArgumentException">Both or neither were supplied.</exception>
    public static ItemRef Create(
        string? path,
        string? itemId,
        string? driveId = null,
        bool allowRoot = false)
    {
        var hasPath = !string.IsNullOrWhiteSpace(path);
        var hasId = !string.IsNullOrWhiteSpace(itemId);

        if (hasPath && hasId)
        {
            throw new ArgumentException(
                "Specify either 'path' or 'itemId', not both.", nameof(path));
        }

        if (hasId)
        {
            return FromId(itemId!, driveId);
        }

        if (hasPath)
        {
            if (!string.IsNullOrWhiteSpace(driveId))
            {
                throw new ArgumentException(
                    "'driveId' can only be used together with 'itemId'; an item on another " +
                    "drive cannot be addressed by path.",
                    nameof(driveId));
            }

            return FromPath(path);
        }

        if (allowRoot)
        {
            return Root;
        }

        throw new ArgumentException("Specify either 'path' or 'itemId'.", nameof(path));
    }

    /// <summary>A short description for log and error messages.</summary>
    public override string ToString() => IsById
        ? DriveId is null ? $"item:{ItemId}" : $"drive:{DriveId}/item:{ItemId}"
        : string.IsNullOrEmpty(Path) ? "(drive root)" : Path;
}
