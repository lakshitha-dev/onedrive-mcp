using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Core.Graph;

/// <summary>
/// Turns an <see cref="ItemRef"/> into a Microsoft Graph resource URL.
/// </summary>
/// <remarks>
/// <para>
/// Graph addresses a drive item three ways, and the path form has an easily-missed quirk: item
/// metadata is <c>/me/drive/root:/{path}</c> with no trailing colon, but any sub-resource is
/// <c>/me/drive/root:/{path}:/children</c> with one. Getting that wrong yields a confusing 400
/// rather than an obvious failure, so it lives in exactly one place.
/// </para>
/// <para>
/// Every path reaching this class goes through <see cref="PathGuard"/> first, so it is already
/// traversal-checked, root-confined and percent-encoded.
/// </para>
/// </remarks>
public sealed class GraphAddress(PathGuard pathGuard)
{
    /// <summary>Base URL for Microsoft Graph v1.0.</summary>
    public const string GraphBaseUrl = "https://graph.microsoft.com/v1.0";

    private readonly PathGuard _pathGuard = pathGuard ?? throw new ArgumentNullException(nameof(pathGuard));

    /// <summary>Resource URL for the caller's drive itself, for quota and drive type.</summary>
    public static string Drive() => $"{GraphBaseUrl}/me/drive";

    /// <summary>Resource URL for the signed-in user.</summary>
    public static string Me() => $"{GraphBaseUrl}/me";

    /// <summary>
    /// Builds the URL for an item, or for one of its sub-resources.
    /// </summary>
    /// <param name="reference">The item to address.</param>
    /// <param name="subResource">
    /// A sub-resource such as <c>children</c>, <c>content</c>, <c>permissions</c> or
    /// <c>createLink</c>. Null addresses the item itself.
    /// </param>
    public string Item(ItemRef reference, string? subResource = null)
    {
        ArgumentNullException.ThrowIfNull(reference);

        if (reference.IsById)
        {
            var itemSegment = Uri.EscapeDataString(reference.ItemId!);

            var root = reference.DriveId is null
                ? $"{GraphBaseUrl}/me/drive/items/{itemSegment}"
                : $"{GraphBaseUrl}/drives/{Uri.EscapeDataString(reference.DriveId)}/items/{itemSegment}";

            return Append(root, subResource);
        }

        var encodedPath = _pathGuard.ToGraphPath(reference.Path);

        if (encodedPath.Length == 0)
        {
            // The drive root has no path segment, so it uses the plain form.
            return Append($"{GraphBaseUrl}/me/drive/root", subResource);
        }

        var addressed = $"{GraphBaseUrl}/me/drive/root:/{encodedPath}";

        // Sub-resources need the closing colon; the item itself must not have one.
        return subResource is null ? addressed : $"{addressed}:/{subResource}";
    }

    /// <summary>
    /// Builds the URL for uploading to a path that may not exist yet, which is why it takes a
    /// path rather than an <see cref="ItemRef"/>.
    /// </summary>
    /// <param name="path">Destination path relative to the drive root.</param>
    /// <param name="subResource"><c>content</c> or <c>createUploadSession</c>.</param>
    public string UploadTarget(string path, string subResource)
    {
        var encodedPath = _pathGuard.ToGraphPath(path);

        if (encodedPath.Length == 0)
        {
            throw new ArgumentException("An upload needs a destination path.", nameof(path));
        }

        return $"{GraphBaseUrl}/me/drive/root:/{encodedPath}:/{subResource}";
    }

    /// <summary>Builds the URL for a search across the caller's drive.</summary>
    /// <param name="query">Raw search text; escaped for OData here.</param>
    public static string Search(string query) =>
        $"{GraphBaseUrl}/me/drive/root/search(q='{ODataEscaper.EscapeStringLiteral(query)}')";

    /// <summary>Builds the URL for the caller's recently used items.</summary>
    public static string Recent() => $"{GraphBaseUrl}/me/drive/recent";

    /// <summary>Builds the URL for a specific permission on an item.</summary>
    public string Permission(ItemRef reference, string permissionId) =>
        $"{Item(reference, "permissions")}/{Uri.EscapeDataString(permissionId)}";

    private static string Append(string root, string? subResource) =>
        subResource is null ? root : $"{root}/{subResource}";
}
