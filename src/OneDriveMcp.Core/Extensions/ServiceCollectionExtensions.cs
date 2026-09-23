using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Core.Extensions;

/// <summary>Registration for the OneDrive Graph layer.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers options, the path and OData guards, and the Graph client.
    /// </summary>
    /// <remarks>
    /// Everything here is a singleton on purpose. The MCP SDK constructs a new tool instance for
    /// each invocation from the message context's service provider, which under a stateless
    /// transport is not an ASP.NET request scope. Scoped dependencies would resolve from a
    /// provider whose lifetime nobody controls; singletons avoid the question entirely.
    /// </remarks>
    public static IServiceCollection AddOneDriveGraph(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<OneDriveOptions>()
            .Bind(configuration.GetSection(OneDriveOptions.SectionName))
            .Validate(
                options => options.LargeFileThresholdBytes <= options.MaxFileSizeBytes,
                "OneDrive:LargeFileThresholdBytes must not exceed OneDrive:MaxFileSizeBytes.")
            .Validate(
                options => options.MaxBase64UploadBytes <= options.MaxFileSizeBytes,
                "OneDrive:MaxBase64UploadBytes must not exceed OneDrive:MaxFileSizeBytes.")
            .Validate(
                options => options.DefaultPageSize <= options.MaxPageSize,
                "OneDrive:DefaultPageSize must not exceed OneDrive:MaxPageSize.")
            .Validate(
                options => options.MaxConcurrentRequests > 0,
                "OneDrive:MaxConcurrentRequests must be greater than zero.")
            .ValidateOnStart();

        services.AddSingleton<PathGuard>();
        services.AddSingleton<GraphAddress>();

        // Graph client. Redirects are not followed: the 302 from /content points at a
        // pre-authenticated URL, and the target has to be validated before anything is fetched
        // from it -- and fetched without the bearer token attached.
        services.AddHttpClient<IOneDriveGraphClient, OneDriveGraphClient>(client =>
            {
                client.Timeout = TimeSpan.FromMinutes(5);
            })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                AllowAutoRedirect = false
            })
            .AddStandardResilienceHandler();

        // Separate client for pre-authenticated content, session and monitor URLs. It never
        // carries an Authorization header, so a redirect cannot leak the caller's Graph token.
        // It has no resilience handler either: a retry here would re-send a chunk the upload
        // session has already accepted. Chunk retries are handled by the client, which knows
        // the offset Graph is actually expecting next.
        services.AddHttpClient(OneDriveGraphClient.ContentHttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromMinutes(10);
        });

        return services;
    }
}
