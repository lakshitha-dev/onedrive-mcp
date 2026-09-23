using System.ComponentModel;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Models;

namespace OneDriveMcp.Core.Tools;

/// <summary>
/// Sharing links and permissions.
/// </summary>
/// <remarks>
/// Creating a link is one call away from exposing a document, so the defaults are deliberately
/// conservative: organisation scope only, an expiry always set, and anonymous links refused
/// unless the deployment has opted in.
/// </remarks>
[McpServerToolType]
public sealed class SharingTools(
    IOneDriveGraphClient graphClient,
    IOptions<OneDriveOptions> options)
{
    private readonly IOneDriveGraphClient _graphClient = graphClient
        ?? throw new ArgumentNullException(nameof(graphClient));

    private readonly OneDriveOptions _options = options?.Value
        ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Creates a sharing link.</summary>
    [McpServerTool(
        Name = "onedrive_create_share_link",
        Title = "Create a OneDrive sharing link",
        Destructive = true,
        UseStructuredContent = true)]
    [Description(
        "Create a sharing link for a OneDrive file or folder. By default the link works only for " +
        "people inside the organisation and expires after a set period. Anyone-with-the-link " +
        "sharing is refused unless the server has been configured to permit it. Revoke a link " +
        "with onedrive_delete_permission using the returned permissionId.")]
    public Task<ShareLink> CreateShareLinkAsync(
        [Description("Path of the item to share, relative to the drive root.")]
        string? path = null,

        [Description("Item id of the item to share, as an alternative to path.")]
        string? itemId = null,

        [Description("'view' for read-only access (default) or 'edit' to allow changes.")]
        string? linkType = null,

        [Description("'organization' for people in the organisation (default) or 'anonymous' for anyone with the link.")]
        string? scope = null,

        [Description("Days until the link expires. Defaults to the server's configured period.")]
        int? expiresInDays = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(path, itemId);
        var resolvedType = ParseLinkType(linkType);
        var resolvedScope = ParseScope(scope);

        // Always set an expiry. A link with no end date is the kind of thing that is still live
        // years after whatever needed it.
        var days = expiresInDays ?? _options.ShareLinkExpiryDays;

        if (days <= 0)
        {
            throw new ArgumentException(
                "expiresInDays must be greater than zero.", nameof(expiresInDays));
        }

        var expiresAt = DateTimeOffset.UtcNow.AddDays(days);

        return _graphClient.CreateShareLinkAsync(
            reference, resolvedType, resolvedScope, expiresAt, cancellationToken);
    }

    /// <summary>Lists the permissions on an item.</summary>
    [McpServerTool(
        Name = "onedrive_list_permissions",
        Title = "List who can access a OneDrive item",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "List who currently has access to a OneDrive file or folder, including any sharing links. " +
        "Use this to check what is exposed before or after sharing something.")]
    public async Task<PermissionList> ListPermissionsAsync(
        [Description("Path of the item, relative to the drive root.")]
        string? path = null,

        [Description("Item id, as an alternative to path.")]
        string? itemId = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(path, itemId);
        var permissions = await _graphClient.ListPermissionsAsync(reference, cancellationToken);

        return new PermissionList(permissions, permissions.Count);
    }

    /// <summary>Revokes a permission.</summary>
    [McpServerTool(
        Name = "onedrive_delete_permission",
        Title = "Revoke access to a OneDrive item",
        Destructive = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Revoke a single permission on a OneDrive file or folder, which is how a sharing link is " +
        "withdrawn. Get the permissionId from onedrive_list_permissions or from the result of " +
        "onedrive_create_share_link.")]
    public async Task<DeleteResult> DeletePermissionAsync(
        [Description("Id of the permission to revoke.")]
        string permissionId,

        [Description("Path of the item, relative to the drive root.")]
        string? path = null,

        [Description("Item id, as an alternative to path.")]
        string? itemId = null,

        CancellationToken cancellationToken = default)
    {
        var reference = ItemRef.Create(path, itemId);

        await _graphClient.DeletePermissionAsync(reference, permissionId, cancellationToken);

        return new DeleteResult(
            Deleted: true,
            Item: reference.ToString(),
            Message: $"Access revoked on '{reference}'. Any link using that permission no longer works.");
    }

    private static string ParseLinkType(string? value) => value?.ToLowerInvariant() switch
    {
        null or "" or "view" => "view",
        "edit" => "edit",
        _ => throw new ArgumentException("linkType must be 'view' or 'edit'.", "linkType")
    };

    private string ParseScope(string? value)
    {
        var resolved = value?.ToLowerInvariant() switch
        {
            null or "" or "organization" => "organization",
            "anonymous" => "anonymous",
            _ => throw new ArgumentException(
                "scope must be 'organization' or 'anonymous'.", "scope")
        };

        if (resolved == "anonymous" && !_options.AllowAnonymousLinks)
        {
            throw new InvalidOperationException(
                "Anonymous sharing links are disabled on this server. A link of that kind can be " +
                "opened by anyone who obtains the URL, so it must be enabled explicitly through " +
                "'OneDrive:AllowAnonymousLinks'. Use scope 'organization' instead.");
        }

        return resolved;
    }
}

/// <summary>
/// The permissions on an item.
/// </summary>
/// <param name="Permissions">Who has access, and how.</param>
/// <param name="Count">Number of permissions.</param>
public sealed record PermissionList(IReadOnlyList<ItemPermission> Permissions, int Count);
