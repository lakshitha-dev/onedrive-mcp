using Microsoft.AspNetCore.Mvc.Testing;

namespace OneDriveMcp.Server.Tests.Fixtures;

/// <summary>
/// Hosts the server once for the whole test assembly.
/// </summary>
/// <remarks>
/// <see cref="WebApplicationFactory{TEntryPoint}"/> starts the host by invoking the real entry
/// point through <c>HostFactoryResolver</c>, which relies on a process-wide diagnostic listener.
/// Two factories starting at once race on it and one of them fails with "the entry point exited
/// without ever building an IHost" -- and which test it lands on varies from run to run. Sharing
/// a single host through a collection fixture removes the race, and makes the suite faster.
/// </remarks>
public sealed class McpServerFixture : IDisposable
{
    private readonly WebApplicationFactory<Program> _factory = new();

    /// <summary>Creates a client against the shared host.</summary>
    public HttpClient CreateClient() => _factory.CreateClient();

    /// <summary>A JSON-RPC client against the shared host.</summary>
    internal McpTestClient CreateMcpClient() => new(CreateClient());

    /// <inheritdoc />
    public void Dispose() => _factory.Dispose();
}

/// <summary>Binds every integration test class to the one shared host.</summary>
[CollectionDefinition(Name)]
public sealed class McpServerCollection : ICollectionFixture<McpServerFixture>
{
    /// <summary>The collection name.</summary>
    public const string Name = "mcp-server";
}
