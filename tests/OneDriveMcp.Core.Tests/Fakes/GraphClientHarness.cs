using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Core.Configuration;
using OneDriveMcp.Core.Graph;
using OneDriveMcp.Core.Security;

namespace OneDriveMcp.Core.Tests.Fakes;

/// <summary>
/// Builds a <see cref="OneDriveGraphClient"/> over stub handlers.
/// </summary>
/// <remarks>
/// Keeps the two transports apart, the same way the real registration does: <see cref="Graph"/>
/// is the token-carrying Graph client, and <see cref="Content"/> is the one used for
/// pre-authenticated content, upload-session and monitor URLs. Tests assert against whichever
/// one should have been used, which is how "no bearer token on the upload URL" becomes testable.
/// </remarks>
internal sealed class GraphClientHarness : IDisposable
{
    private readonly HttpClient _graphClient;
    private readonly HttpClient _contentClient;

    public GraphClientHarness(Action<OneDriveOptions>? configure = null, string? token = "test-token")
    {
        var options = new OneDriveOptions();
        configure?.Invoke(options);

        Options = Microsoft.Extensions.Options.Options.Create(options);

        _graphClient = new HttpClient(Graph) { BaseAddress = new Uri("https://graph.microsoft.com") };
        _contentClient = new HttpClient(Content);

        var pathGuard = new PathGuard(Options);

        Client = new OneDriveGraphClient(
            _graphClient,
            new StubHttpClientFactory(_contentClient),
            new StaticGraphTokenService(token),
            new GraphAddress(pathGuard),
            pathGuard,
            Options,
            NullLogger<OneDriveGraphClient>.Instance);
    }

    /// <summary>Handler behind the token-carrying Graph client.</summary>
    public StubHttpMessageHandler Graph { get; } = new();

    /// <summary>Handler behind the unauthenticated content client.</summary>
    public StubHttpMessageHandler Content { get; } = new();

    /// <summary>The client under test.</summary>
    public IOneDriveGraphClient Client { get; }

    /// <summary>The options the client was built with.</summary>
    public IOptions<OneDriveOptions> Options { get; }

    public void Dispose()
    {
        _graphClient.Dispose();
        _contentClient.Dispose();
    }

    private sealed class StubHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
}
