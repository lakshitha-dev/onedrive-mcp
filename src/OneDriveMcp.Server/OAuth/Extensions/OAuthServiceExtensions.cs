using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Endpoints;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.OAuth.Extensions;

/// <summary>Registration and routing for the built-in authorization server.</summary>
public static class OAuthServiceExtensions
{
    /// <summary>Registers the authorization server's services.</summary>
    public static IServiceCollection AddOAuthServer(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(OAuthServerOptions.SectionName);

        services.AddOptions<OAuthServerOptions>()
            .Bind(section)
            // An issuer shared between deployments means each would accept the other's tokens, so
            // a token minted against a test environment would unlock production. Checked at
            // startup rather than left to be discovered.
            .Validate(
                options => !options.Enabled || options.ResolveIssuer() is { Length: > 0 },
                "OAuthServer:Issuer (or OAuthServer:PublicBaseUrl) must be set to a value unique " +
                "to this deployment. Sharing an issuer allows tokens to be replayed between them.")
            .Validate(
                options => !options.Enabled
                    || !string.Equals(options.ResolveIssuer(), "onedrive-mcp", StringComparison.OrdinalIgnoreCase),
                "OAuthServer:Issuer must not be left at the placeholder value.")
            .Validate(
                options => options.AccessTokenLifetimeMinutes is > 0 and <= 1440,
                "OAuthServer:AccessTokenLifetimeMinutes must be between 1 and 1440.")
            .Validate(
                options => options.RefreshTokenLifetimeHours is > 0 and <= 8760,
                "OAuthServer:RefreshTokenLifetimeHours must be between 1 and 8760.")
            .Validate(
                options => options.AuthorizationCodeLifetimeMinutes is > 0 and <= 60,
                "OAuthServer:AuthorizationCodeLifetimeMinutes must be between 1 and 60.")
            .ValidateOnStart();

        if (!section.GetValue<bool>(nameof(OAuthServerOptions.Enabled)))
        {
            return services;
        }

        services.AddMemoryCache();

        services.AddSingleton<OAuthSigningKeyProvider>();
        services.AddHostedService<OAuthSigningKeyInitializer>();

        services.AddSingleton<IOAuthClientStore, InMemoryOAuthClientStore>();
        services.AddSingleton<IAccessTokenDenyList, InMemoryAccessTokenDenyList>();
        services.AddSingleton<ConsentSessionStore>();
        services.AddSingleton<OAuthTokenService>();

        // The stores above are in-memory. Without this, a restart forgets which clients are
        // registered and which tokens have been revoked -- and a revoked token starts working
        // again, which on App Service happens every time the app recycles.
        services.AddSingleton<OAuthStatePersistence>();
        services.AddHostedService(provider => provider.GetRequiredService<OAuthStatePersistence>());

        return services;
    }

    /// <summary>Maps the authorization server's endpoints.</summary>
    public static IEndpointRouteBuilder MapOAuthServer(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapOAuthDiscovery();
        endpoints.MapClientRegistration();
        endpoints.MapOAuthAuthorize();
        endpoints.MapOAuthToken();
        endpoints.MapOAuthRevocation();

        return endpoints;
    }
}
