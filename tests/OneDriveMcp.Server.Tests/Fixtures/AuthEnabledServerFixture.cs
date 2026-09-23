using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace OneDriveMcp.Server.Tests.Fixtures;

/// <summary>
/// Hosts the server with Entra authentication switched on.
/// </summary>
/// <remarks>
/// The tenant and audience are fictitious. Nothing here validates a real token -- these tests
/// cover the unauthenticated paths, where the interesting behaviour is the challenge the server
/// issues rather than any signature check.
/// </remarks>
public sealed class AuthEnabledServerFixture : IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;

    public AuthEnabledServerFixture()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Auth:EnableOAuth", "true");
                builder.UseSetting("Auth:TenantId", "00000000-0000-0000-0000-000000000001");
                builder.UseSetting("Auth:Audience", "api://00000000-0000-0000-0000-000000000002");
                builder.UseSetting("Auth:PublicBaseUrl", "https://onedrive-mcp.test");

                // Without this the dev token from the developer's own environment could leak in
                // and change what these tests exercise.
                builder.UseSetting("Dev:GraphAccessToken", string.Empty);
            });
    }

    /// <summary>Creates a client against the authenticated host.</summary>
    public HttpClient CreateClient() => _factory.CreateClient();

    /// <inheritdoc />
    public void Dispose() => _factory.Dispose();
}

/// <summary>Binds the authentication tests to their own shared host.</summary>
[CollectionDefinition(Name)]
public sealed class AuthEnabledServerCollection : ICollectionFixture<AuthEnabledServerFixture>
{
    /// <summary>The collection name.</summary>
    public const string Name = "mcp-server-auth";
}
