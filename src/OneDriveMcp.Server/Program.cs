using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Core.Extensions;
using OneDriveMcp.Core.Tools;
using OneDriveMcp.Server.Auth;
using OneDriveMcp.Server.Filters;
using OneDriveMcp.Server.Middleware;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Extensions;
using Serilog;

// A bootstrap logger so failures during host construction are not silent.
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext());

    builder.WebHost.ConfigureKestrel(options =>
    {
        // Tool arguments arrive as JSON-RPC bodies. Cap them well below anything that could
        // exhaust memory; the base64 upload cap is tighter still.
        options.Limits.MaxRequestBodySize = 10 * 1024 * 1024;

        // Must be suppressed here rather than in middleware. Kestrel writes this header after the
        // pipeline has run, so removing it from HttpContext.Response.Headers has no effect --
        // something only a real server reveals, because TestServer never adds it at all.
        options.AddServerHeader = false;
    });

    var authOptions = builder.Configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()
        ?? new AuthOptions();

    var devGraphToken = builder.Configuration["Dev:GraphAccessToken"];
    var useDevToken = !string.IsNullOrWhiteSpace(devGraphToken);

    if (builder.Environment.IsProduction())
    {
        if (useDevToken)
        {
            throw new InvalidOperationException(
                "Dev:GraphAccessToken is set in Production. It ignores the caller's identity " +
                "entirely and would serve every request as one user. Remove it.");
        }

        if (!authOptions.EnableOAuth)
        {
            throw new InvalidOperationException(
                "Auth:EnableOAuth is false in Production, which would leave the MCP endpoint " +
                "anonymous and expose the configured account's OneDrive to any caller.");
        }
    }

    builder.Services.Configure<AuthOptions>(
        builder.Configuration.GetSection(AuthOptions.SectionName));

    // The credential accessor reads the request currently in flight, which is correct because
    // the transport is stateless: every tool call is its own independent POST.
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddSingleton<IUserCredentialAccessor, HttpUserCredentialAccessor>();

    // Refresh tokens are encrypted with Data Protection. The keyring is pinned to a stable
    // application name and, on App Service, to the durable /home mount -- otherwise a restart
    // would generate new keys and every stored token would become undecryptable.
    var dataProtection = builder.Services.AddDataProtection()
        .SetApplicationName("OneDriveMcp");

    if (Directory.Exists("/home"))
    {
        var keyDirectory = Directory.CreateDirectory(Path.Combine("/home", "data", "dp-keys"));
        dataProtection.PersistKeysToFileSystem(keyDirectory);
    }

    // Holds the delegated Microsoft access captured at consent, which is what lets a caller
    // presenting a token this server issued itself still reach Graph.
    builder.Services.AddSingleton<IEntraRefreshTokenStore, EntraRefreshTokenStore>();

    // Registered before authentication, which reads the same options to decide whether to add
    // the self-issued token scheme and the issuer router.
    builder.Services.AddOAuthServer(builder.Configuration);
    builder.Services.AddEntraAuthentication(builder.Configuration);
    builder.Services.AddOneDriveGraph(builder.Configuration);

    if (useDevToken)
    {
        // Development shortcut: a token pasted from Graph Explorer exercises the whole tool
        // surface, which is what let the Graph layer be proven before any OAuth existed.
        builder.Services.AddSingleton<IGraphTokenService>(
            _ => new StaticGraphTokenService(devGraphToken));
    }
    else
    {
        // Exchanges the caller's own Entra token for a Graph token, so the server acts strictly
        // as that user and sees only their drive.
        builder.Services.AddHttpClient<IGraphTokenService, OboGraphTokenService>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        });
    }

    builder.Services.AddSingleton<ToolCallFilter>();

    builder.Services
        .AddMcpServer(options =>
        {
            options.ServerInfo = new Implementation
            {
                Name = "onedrive-mcp",
                Version = ThisAssembly.Version
            };
        })
        .WithHttpTransport(httpOptions =>
        {
            // Stateless is the default as of the 2026-07-28 protocol revision: SEP-2567 removed
            // Mcp-Session-Id and SEP-2575 removed the initialize handshake, so the transport no
            // longer tracks state between requests. Stated explicitly because it is load-bearing:
            // every tool call is an independent request served in its own execution context,
            // which is what makes IHttpContextAccessor the correct way to read the caller's
            // token. It also means the server scales out without session affinity.
            //
            // The trade-off is that the server cannot initiate requests, so sampling, elicitation
            // and roots are unavailable. No tool here depends on them; destructive operations are
            // guarded by tool annotations and config gates instead of an interactive confirmation.
            httpOptions.SessionMode = HttpServerSessionMode.Stateless;
        })
        // Registered explicitly rather than via WithToolsFromAssembly(): that overload defaults
        // to the *calling* assembly, which is this host, and would silently register nothing
        // because every tool type lives in OneDriveMcp.Core.
        .WithTools<BrowseTools>()
        .WithTools<WriteTools>()
        .WithTools<SearchTools>()
        .WithTools<SharingTools>()
        .WithTools<DiagnosticsTools>()
        .WithRequestFilters(filters => filters.AddCallToolFilter(next => (context, cancellationToken) =>
        {
            var filter = context.Services!.GetRequiredService<ToolCallFilter>();

            return filter.InvokeAsync(context, next, cancellationToken);
        }));

    builder.Services.AddHealthChecks();

    var app = builder.Build();

    app.UseSerilogRequestLogging();

    if (!app.Environment.IsDevelopment())
    {
        app.UseHttpsRedirection();
        app.UseHsts();
    }

    app.UseMiddleware<SecurityHeadersMiddleware>();

    if (authOptions.EnableOAuth)
    {
        app.UseAuthentication();
        app.UseAuthorization();
    }

    app.MapHealthChecks("/health");
    app.MapHealthChecks("/health/live");
    app.MapHealthChecks("/health/ready");

    var oauthServerOptions = builder.Configuration
        .GetSection(OAuthServerOptions.SectionName).Get<OAuthServerOptions>() ?? new OAuthServerOptions();

    if (oauthServerOptions.Enabled)
    {
        app.MapOAuthServer();

        if (string.IsNullOrEmpty(oauthServerOptions.RegistrationInitialAccessToken)
            && !app.Environment.IsDevelopment())
        {
            Log.Warning(
                "OAuthServer:RegistrationInitialAccessToken is not set, so /oauth/register is " +
                "open to anyone who can reach this server.");
        }
    }

    var mcp = app.MapMcp("/mcp");

    if (authOptions.EnableOAuth)
    {
        // The gateway this was extracted from mapped its MCP endpoint with no authorization at
        // all, relying on a custom middleware for it. Saying so here means the endpoint cannot
        // quietly become anonymous if that middleware is ever removed.
        mcp.RequireAuthorization();
    }
    else
    {
        Log.Warning(
            "Auth:EnableOAuth is false. The MCP endpoint is anonymous; do not expose this " +
            "server beyond localhost.");
    }

    if (useDevToken)
    {
        Log.Warning(
            "Dev:GraphAccessToken is set. Every caller is served as the owner of that token; " +
            "this is for local development only.");
    }

    Log.Information("OneDrive MCP server starting ({Environment})", app.Environment.EnvironmentName);

    app.Run();
    return 0;
}
catch (Exception ex) when (!IsHostControlFlow(ex))
{
    Log.Fatal(ex, "OneDrive MCP server terminated unexpectedly");
    return 1;
}
finally
{
    Log.CloseAndFlush();
}

// WebApplicationFactory drives this same entry point and aborts it, once it has captured the
// host, by throwing an internal StopTheHostException from HostFactoryResolver. Catching that
// would leave the factory reporting "the entry point exited without ever building an IHost",
// so both host-control-flow exceptions have to pass straight through.
static bool IsHostControlFlow(Exception exception) =>
    exception is HostAbortedException
    || string.Equals(exception.GetType().Name, "StopTheHostException", StringComparison.Ordinal);

/// <summary>Assembly metadata surfaced to MCP clients in the server handshake.</summary>
internal static class ThisAssembly
{
    public const string Version = "0.1.0";
}

/// <summary>Exposed so the integration tests can drive the host with WebApplicationFactory.</summary>
public partial class Program;
