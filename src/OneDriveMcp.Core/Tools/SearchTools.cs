using System.ComponentModel;
using ModelContextProtocol.Server;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Models;

namespace OneDriveMcp.Core.Tools;

/// <summary>
/// Finding files without knowing their path.
/// </summary>
/// <remarks>
/// Results are addressed by id rather than path, because search can return items whose path is
/// not usable for a follow-up call. Both tools page, since a real drive returns far more than
/// fits in one response.
/// </remarks>
[McpServerToolType]
public sealed class SearchTools(IOneDriveGraphClient graphClient)
{
    private readonly IOneDriveGraphClient _graphClient = graphClient
        ?? throw new ArgumentNullException(nameof(graphClient));

    /// <summary>Searches the drive.</summary>
    [McpServerTool(
        Name = "onedrive_search",
        Title = "Search OneDrive",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "Search the caller's OneDrive for files and folders matching a query. Matches names and, " +
        "for supported formats, file contents. Use this when the path of a file is unknown. " +
        "Pass the id from a result to the other tools.")]
    public Task<PagedItems> SearchAsync(
        [Description("What to search for, such as 'quarterly budget' or 'invoice.pdf'.")]
        string query,

        [Description("Maximum items to return in this page.")]
        int? pageSize = null,

        [Description("Cursor from a previous call's nextCursor, to fetch the following page.")]
        string? cursor = null,

        CancellationToken cancellationToken = default)
    {
        return _graphClient.SearchAsync(query, pageSize, cursor, cancellationToken);
    }

    /// <summary>Lists recently used items.</summary>
    [McpServerTool(
        Name = "onedrive_list_recent",
        Title = "List recent OneDrive files",
        ReadOnly = true,
        Idempotent = true,
        UseStructuredContent = true)]
    [Description(
        "List the files the caller used most recently across their OneDrive. Useful when someone " +
        "refers to a document they were 'just working on' without naming it.")]
    public Task<PagedItems> ListRecentAsync(
        [Description("Maximum items to return in this page.")]
        int? pageSize = null,

        [Description("Cursor from a previous call's nextCursor, to fetch the following page.")]
        string? cursor = null,

        CancellationToken cancellationToken = default)
    {
        return _graphClient.ListRecentAsync(pageSize, cursor, cancellationToken);
    }
}
