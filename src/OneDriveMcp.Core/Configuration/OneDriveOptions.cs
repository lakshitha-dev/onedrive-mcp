namespace OneDriveMcp.Core.Configuration;

/// <summary>
/// Options for OneDrive access, bound from the <c>OneDrive</c> configuration section.
/// </summary>
public sealed class OneDriveOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "OneDrive";

    /// <summary>Entra tenant used for the on-behalf-of exchange.</summary>
    public string? OboTenantId { get; set; }

    /// <summary>Entra application (client) id used for the on-behalf-of exchange.</summary>
    public string? OboClientId { get; set; }

    /// <summary>
    /// Client secret for the on-behalf-of exchange. Outside Development this must be a Key Vault
    /// reference (<c>@Microsoft.KeyVault(...)</c>) rather than a literal.
    /// </summary>
    public string? OboClientSecret { get; set; }

    /// <summary>
    /// Graph scopes requested during token exchange. <c>offline_access</c> is appended
    /// automatically if absent, because without it the refresh-token path silently degrades.
    /// </summary>
    public string OboGraphScope { get; set; } =
        "https://graph.microsoft.com/Files.ReadWrite https://graph.microsoft.com/User.Read offline_access";

    /// <summary>Fallback cache lifetime when a Graph token carries no readable expiry.</summary>
    public int OboTokenCacheMinutes { get; set; } = 55;

    /// <summary>Maximum tool invocations executing against Graph at once.</summary>
    public int MaxConcurrentRequests { get; set; } = 10;

    /// <summary>Largest file returned as text. Larger files must be fetched by download URL.</summary>
    public long MaxTextFileReadBytes { get; set; } = 50 * 1024;

    /// <summary>Largest file this server will upload.</summary>
    public long MaxFileSizeBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>Above this size an upload switches from a simple PUT to a resumable session.</summary>
    public long LargeFileThresholdBytes { get; set; } = 4 * 1024 * 1024;

    /// <summary>
    /// Cap on decoded base64 upload payloads. Base64 inflates by a third and materialises twice
    /// in memory, so this is deliberately well below <see cref="MaxFileSizeBytes"/>.
    /// </summary>
    public long MaxBase64UploadBytes { get; set; } = 3 * 1024 * 1024;

    /// <summary>
    /// Optional prefix every path is confined to, relative to the drive root. Empty means the
    /// whole drive. Setting it reinstates something like the app-folder sandbox.
    /// </summary>
    public string RootPath { get; set; } = string.Empty;

    /// <summary>
    /// Path prefixes (relative to <see cref="RootPath"/>) that tools may never touch, such as
    /// <c>Apps/</c> or <c>Recordings/</c>. Matched case-insensitively on whole segments.
    /// </summary>
    public IList<string> DeniedPathPrefixes { get; set; } = [];

    /// <summary>
    /// Whether <c>onedrive_get_download_url</c> may hand out pre-authenticated URLs. These need
    /// no credentials to fetch and end up in the model transcript, so this defaults to off.
    /// </summary>
    public bool AllowDownloadUrls { get; set; }

    /// <summary>
    /// Whether sharing links may use <c>anonymous</c> scope. Defaults to off; without it links
    /// are restricted to the organisation.
    /// </summary>
    public bool AllowAnonymousLinks { get; set; }

    /// <summary>Default lifetime applied to created sharing links.</summary>
    public int ShareLinkExpiryDays { get; set; } = 7;

    /// <summary>Largest page size a list or search tool will request from Graph.</summary>
    public int MaxPageSize { get; set; } = 200;

    /// <summary>Page size used when a caller does not specify one.</summary>
    public int DefaultPageSize { get; set; } = 50;
}
