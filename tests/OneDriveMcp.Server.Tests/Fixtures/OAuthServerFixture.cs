using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace OneDriveMcp.Server.Tests.Fixtures;

/// <summary>Hosts the server with the built-in authorization server switched on.</summary>
/// <remarks>
/// No Key Vault is configured, so the signing key is generated in memory for the lifetime of the
/// fixture — which is what these tests want: real signatures, no external dependency.
/// </remarks>
public sealed class OAuthServerFixture : IDisposable
{
    /// <summary>The issuer the fixture is configured with.</summary>
    public const string Issuer = "https://onedrive-mcp.test";

    private readonly WebApplicationFactory<Program> _factory;

    public OAuthServerFixture()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Auth:EnableOAuth", "true");
                builder.UseSetting("Auth:TenantId", "00000000-0000-0000-0000-000000000001");
                builder.UseSetting("Auth:Audience", "api://00000000-0000-0000-0000-000000000002");
                builder.UseSetting("Auth:PublicBaseUrl", Issuer);

                builder.UseSetting("OAuthServer:Enabled", "true");
                builder.UseSetting("OAuthServer:Issuer", Issuer);
                builder.UseSetting("OAuthServer:PublicBaseUrl", Issuer);

                builder.UseSetting("Dev:GraphAccessToken", string.Empty);
            });
    }

    /// <summary>Creates a client against the host.</summary>
    public HttpClient CreateClient() => _factory.CreateClient();

    /// <summary>Creates a client that does not follow redirects, for the consent flow.</summary>
    public HttpClient CreateNonRedirectingClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    /// <summary>Resolves a service from the host, for testing the token service directly.</summary>
    public T GetService<T>() where T : notnull => _factory.Services.GetRequiredService<T>();

    /// <inheritdoc />
    public void Dispose() => _factory.Dispose();
}

/// <summary>Binds the authorization server tests to their own shared host.</summary>
[CollectionDefinition(Name)]
public sealed class OAuthServerCollection : ICollectionFixture<OAuthServerFixture>
{
    /// <summary>The collection name.</summary>
    public const string Name = "mcp-server-oauth";
}
