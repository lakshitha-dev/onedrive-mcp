using System.Text.Json;
using OneDriveMcp.Core.Models;

namespace OneDriveMcp.Core.Graph;

/// <summary>Maps Graph JSON onto the models the tools return.</summary>
internal static class DriveItemMapper
{
    /// <summary>The <c>$select</c> list used for every item query, to keep responses small.</summary>
    public const string ItemSelect =
        "id,name,size,lastModifiedDateTime,file,folder,webUrl,parentReference,remoteItem";

    /// <summary>Maps a Graph <c>driveItem</c>.</summary>
    public static DriveItem ToDriveItem(JsonElement element)
    {
        // A shared item arrives wrapped: the useful facts live under remoteItem and the id and
        // driveId that actually address it are on remoteItem.parentReference, not the outer one.
        var source = element.TryGetProperty("remoteItem", out var remote) ? remote : element;

        var isFolder = source.TryGetProperty("folder", out var folder);

        var parentPath = TryGetString(source, "parentReference", "path");
        var name = GetString(source, "name") ?? GetString(element, "name") ?? string.Empty;

        return new DriveItem(
            Id: GetString(source, "id") ?? GetString(element, "id") ?? string.Empty,
            Name: name,
            Path: BuildRelativePath(parentPath, name),
            IsFolder: isFolder,
            Size: GetInt64(source, "size") ?? 0,
            LastModified: GetString(source, "lastModifiedDateTime"),
            MimeType: source.TryGetProperty("file", out var file) ? GetString(file, "mimeType") : null,
            WebUrl: GetString(source, "webUrl"),
            ChildCount: isFolder ? GetInt32(folder, "childCount") : null,
            DriveId: TryGetString(source, "parentReference", "driveId"));
    }

    /// <summary>Maps the <c>value</c> array of a Graph collection response.</summary>
    public static List<DriveItem> ToDriveItems(JsonElement root)
    {
        var items = new List<DriveItem>();

        if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in value.EnumerateArray())
            {
                items.Add(ToDriveItem(element));
            }
        }

        return items;
    }

    /// <summary>Maps a Graph <c>drive</c> resource.</summary>
    public static Models.DriveInfo ToDriveInfo(JsonElement element)
    {
        long? total = null;
        long? used = null;
        long? remaining = null;

        if (element.TryGetProperty("quota", out var quota))
        {
            total = GetInt64(quota, "total");
            used = GetInt64(quota, "used");
            remaining = GetInt64(quota, "remaining");
        }

        string? owner = null;

        if (element.TryGetProperty("owner", out var ownerElement) &&
            ownerElement.TryGetProperty("user", out var user))
        {
            owner = GetString(user, "displayName");
        }

        return new Models.DriveInfo(
            DriveId: GetString(element, "id"),
            DriveType: GetString(element, "driveType"),
            OwnerDisplayName: owner,
            TotalBytes: total,
            UsedBytes: used,
            RemainingBytes: remaining,
            WebUrl: GetString(element, "webUrl"));
    }

    /// <summary>Maps a Graph <c>permission</c> resource.</summary>
    public static ItemPermission ToPermission(JsonElement element)
    {
        var roles = new List<string>();

        if (element.TryGetProperty("roles", out var rolesElement) &&
            rolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var role in rolesElement.EnumerateArray())
            {
                var value = role.GetString();

                if (value is not null)
                {
                    roles.Add(value);
                }
            }
        }

        string? grantedTo = null;

        if (element.TryGetProperty("grantedToV2", out var granted) &&
            granted.TryGetProperty("user", out var grantedUser))
        {
            grantedTo = GetString(grantedUser, "displayName") ?? GetString(grantedUser, "email");
        }

        var hasLink = element.TryGetProperty("link", out var link);

        return new ItemPermission(
            Id: GetString(element, "id") ?? string.Empty,
            Roles: roles,
            GrantedTo: grantedTo,
            LinkType: hasLink ? GetString(link, "type") : null,
            LinkScope: hasLink ? GetString(link, "scope") : null,
            LinkUrl: hasLink ? GetString(link, "webUrl") : null,
            ExpiresAt: GetString(element, "expirationDateTime"),
            IsInherited: element.TryGetProperty("inheritedFrom", out var inherited)
                && inherited.ValueKind != JsonValueKind.Null);
    }

    /// <summary>Maps the response of a <c>createLink</c> call.</summary>
    public static ShareLink ToShareLink(JsonElement element)
    {
        var hasLink = element.TryGetProperty("link", out var link);

        return new ShareLink(
            PermissionId: GetString(element, "id"),
            Url: hasLink ? GetString(link, "webUrl") : null,
            LinkType: hasLink ? GetString(link, "type") : null,
            Scope: hasLink ? GetString(link, "scope") : null,
            ExpiresAt: GetString(element, "expirationDateTime"));
    }

    /// <summary>Reads <c>@odata.nextLink</c>, if present.</summary>
    public static string? GetNextLink(JsonElement root) =>
        root.TryGetProperty("@odata.nextLink", out var next) ? next.GetString() : null;

    /// <summary>
    /// Converts a Graph <c>parentReference.path</c> such as <c>/drive/root:/Documents</c> into a
    /// path relative to the drive root. Returns null when the item is on another drive, where a
    /// path is not usable for addressing.
    /// </summary>
    private static string? BuildRelativePath(string? parentPath, string name)
    {
        if (parentPath is null)
        {
            return null;
        }

        const string RootMarker = "/root:";
        var markerIndex = parentPath.IndexOf(RootMarker, StringComparison.OrdinalIgnoreCase);

        if (markerIndex < 0)
        {
            return null;
        }

        var relative = parentPath[(markerIndex + RootMarker.Length)..].Trim('/');

        // Graph percent-encodes this path; decode so it round-trips through our own escaping.
        relative = Uri.UnescapeDataString(relative);

        return relative.Length == 0 ? name : $"{relative}/{name}";
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? TryGetString(JsonElement element, string parent, string property) =>
        element.TryGetProperty(parent, out var parentElement)
            ? GetString(parentElement, property)
            : null;

    private static long? GetInt64(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt64()
            : null;

    private static int? GetInt32(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(property, out var value)
            && value.ValueKind == JsonValueKind.Number
                ? value.GetInt32()
                : null;
}
