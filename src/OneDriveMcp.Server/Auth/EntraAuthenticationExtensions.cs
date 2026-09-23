using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.AspNetCore.Authentication;
using ModelContextProtocol.Authentication;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Core.Auth;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.Auth;

/// <summary>Registers the authentication schemes the MCP endpoint and consent flow use.</summary>
public static class EntraAuthenticationExtensions
{
    /// <summary>Validates Entra-issued caller tokens.</summary>
    public const string EntraScheme = "AzureAd";

    /// <summary>Validates tokens this server issued itself.</summary>
    public const string OAuthServerScheme = "OAuthServer";

    /// <summary>Routes a bearer token to whichever scheme can validate it.</summary>
    public const string DualScheme = "DualJwt";

    /// <summary>
    /// Adds token validation for the MCP endpoint, plus the interactive sign-in used by consent.
    /// </summary>
    public static IServiceCollection AddEntraAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>()
            ?? new AuthOptions();

        var oauthServer = configuration.GetSection(OAuthServerOptions.SectionName).Get<OAuthServerOptions>()
            ?? new OAuthServerOptions();

        if (!options.EnableOAuth)
        {
            return services;
        }

        if (string.IsNullOrWhiteSpace(options.TenantId) || string.IsNullOrWhiteSpace(options.Audience))
        {
            throw new InvalidOperationException(
                "Auth:EnableOAuth is true but Auth:TenantId and Auth:Audience are not both set. " +
                "Without them no token can be validated and every request would be rejected.");
        }

        // Entra issues v1 and v2 tokens under different issuer hostnames, and which one a caller
        // gets depends on the app registration rather than on anything this server controls.
        string[] entraIssuers =
        [
            $"https://sts.windows.net/{options.TenantId}/",
            $"https://login.microsoftonline.com/{options.TenantId}/v2.0"
        ];

        // Accept the audience with and without the api:// prefix, since tokens differ on this.
        // Nulls are filtered out: passing a null through as a valid audience makes the JWT
        // handler accept any audience at all.
        var validAudiences = new[] { options.Audience, StripScheme(options.Audience) }
            .Where(audience => !string.IsNullOrWhiteSpace(audience))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var builder = services.AddAuthentication(authentication =>
        {
            // With the authorization server on, a caller's token may come from Entra or from this
            // server, so the default has to be the router rather than either one.
            authentication.DefaultAuthenticateScheme =
                oauthServer.Enabled ? DualScheme : EntraScheme;

            // The MCP handler issues the challenge when no token is presented, because it is the
            // one that adds `WWW-Authenticate: Bearer resource_metadata="..."`. Leaving JwtBearer
            // as the challenge scheme produces a bare `Bearer`, which tells a client it needs to
            // authenticate but not where.
            authentication.DefaultChallengeScheme = McpAuthenticationDefaults.AuthenticationScheme;
        });

        builder.AddJwtBearer(EntraScheme, jwt =>
        {
            jwt.Authority = $"https://login.microsoftonline.com/{options.TenantId}/v2.0";
            jwt.Audience = options.Audience;
            jwt.MapInboundClaims = false;

            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = entraIssuers,
                ValidateAudience = true,
                ValidAudiences = validAudiences,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(2)
            };

            jwt.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    // Log the reason but never the token: a rejected token is still a credential.
                    LoggerFor(context.HttpContext).LogInformation(
                        "Entra token validation failed: {Reason}", context.Exception.GetType().Name);

                    return Task.CompletedTask;
                }
            };
        });

        if (oauthServer.Enabled)
        {
            AddSelfIssuedTokenValidation(services, builder);
            AddIssuerRouting(builder, entraIssuers);
            AddConsentSignIn(builder, options, configuration);
        }

        builder.AddMcp(mcp =>
        {
            mcp.ResourceMetadata = new ProtectedResourceMetadata
            {
                ResourceName = "OneDrive MCP Server",
                ScopesSupported = [options.RequiredScope],
                BearerMethodsSupported = ["header"]
            };

            if (Uri.TryCreate(options.PublicBaseUrl, UriKind.Absolute, out var baseUrl))
            {
                mcp.ResourceMetadata.Resource = baseUrl.AbsoluteUri;

                // Point clients at whichever authority actually issues tokens they can use here.
                mcp.ResourceMetadata.AuthorizationServers =
                [
                    oauthServer.Enabled
                        ? baseUrl.AbsoluteUri.TrimEnd('/')
                        : $"https://login.microsoftonline.com/{options.TenantId}/v2.0"
                ];
            }
        });

        services.AddAuthorization();

        return services;
    }

    /// <summary>Validates the JWTs this server signs for its DCR clients.</summary>
    private static void AddSelfIssuedTokenValidation(
        IServiceCollection services,
        AuthenticationBuilder builder)
    {
        builder.AddJwtBearer(OAuthServerScheme, _ => { });

        services
            .AddOptions<JwtBearerOptions>(OAuthServerScheme)
            .Configure<OAuthSigningKeyProvider, IOptionsMonitor<OAuthServerOptions>>(
                (jwt, signingKeys, oauthOptions) =>
                {
                    var issuer = oauthOptions.CurrentValue.ResolveIssuer();

                    jwt.MapInboundClaims = false;

                    jwt.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = issuer,
                        ValidateAudience = true,

                        // Audience equals issuer: this server both mints the token and is the only
                        // resource meant to accept it.
                        ValidAudience = issuer,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,

                        // Resolved per validation rather than captured once, so a key created or
                        // rotated after these options were first materialised is still honoured.
                        IssuerSigningKeyResolver = (_, _, _, _) => signingKeys.ValidationKeys
                    };

                    jwt.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            // A self-issued token is otherwise valid until it expires, so
                            // revocation has to be enforced on every request.
                            var denyList = context.HttpContext.RequestServices
                                .GetRequiredService<IAccessTokenDenyList>();

                            var rawToken = (context.SecurityToken as JsonWebToken)?.EncodedToken;

                            if (rawToken is not null && denyList.IsRevoked(rawToken))
                            {
                                context.Fail("This access token has been revoked.");
                                return Task.CompletedTask;
                            }

                            // Detecting a replayed refresh token revokes the whole grant. Access
                            // tokens are self-contained and would otherwise keep working until
                            // they expired, leaving the holder of a stolen one with access for
                            // the rest of its lifetime -- the exact window reuse detection is
                            // meant to close.
                            var family = context.Principal?.FindFirst(OAuthTokenService.FamilyClaim)?.Value;

                            if (denyList.IsFamilyRevoked(family))
                            {
                                context.Fail("The session this access token belongs to has been revoked.");
                            }

                            return Task.CompletedTask;
                        }
                    };
                });
    }

    /// <summary>
    /// Routes each bearer token to the scheme that can validate it, by peeking at its issuer.
    /// </summary>
    private static void AddIssuerRouting(AuthenticationBuilder builder, string[] entraIssuers)
    {
        builder.AddPolicyScheme(DualScheme, DualScheme, policy =>
        {
            policy.ForwardDefaultSelector = context =>
            {
                var header = context.Request.Headers.Authorization.FirstOrDefault();

                if (string.IsNullOrEmpty(header) ||
                    !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    // No bearer token. A browser mid-consent has a cookie instead.
                    return context.Request.Cookies.ContainsKey(".AspNetCore.Cookies")
                        ? CookieAuthenticationDefaults.AuthenticationScheme
                        : EntraScheme;
                }

                var issuer = PeekIssuer(header["Bearer ".Length..].Trim());

                // The issuer here is unverified — it is read from an unvalidated token purely to
                // choose a validator. Whichever scheme is selected then verifies the signature,
                // so a forged issuer only routes an invalid token to a handler that rejects it.
                return issuer is not null && !entraIssuers.Contains(issuer, StringComparer.Ordinal)
                    ? OAuthServerScheme
                    : EntraScheme;
            };
        });
    }

    /// <summary>Adds the cookie and OpenID Connect schemes used by the consent page.</summary>
    private static void AddConsentSignIn(
        AuthenticationBuilder builder,
        AuthOptions options,
        IConfiguration configuration)
    {
        builder.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, cookie =>
        {
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.IsEssential = true;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;

            // Lax, not Strict: the browser arrives here on a top-level redirect back from Entra,
            // and Strict would drop the cookie on exactly that navigation.
            cookie.Cookie.SameSite = SameSiteMode.Lax;

            // The cookie only has to survive the consent round trip.
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            cookie.SlidingExpiration = false;
        });

        builder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, oidc =>
        {
            oidc.Authority = $"https://login.microsoftonline.com/{options.TenantId}/v2.0";
            oidc.ClientId = StripScheme(options.Audience) ?? options.Audience;
            oidc.ClientSecret = configuration["OneDrive:OboClientSecret"];
            oidc.ResponseType = OpenIdConnectResponseType.Code;
            oidc.UsePkce = true;
            oidc.MapInboundClaims = false;
            oidc.GetClaimsFromUserInfoEndpoint = true;
            oidc.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

            oidc.Scope.Clear();
            oidc.Scope.Add("openid");
            oidc.Scope.Add("profile");
            oidc.Scope.Add("email");

            // offline_access is what makes Entra issue a refresh token at all, and the Graph
            // scopes are what make that refresh token redeemable for OneDrive access. Without
            // both, a client holding a self-issued token could never reach Graph.
            oidc.Scope.Add("offline_access");
            oidc.Scope.Add("https://graph.microsoft.com/Files.ReadWrite");
            oidc.Scope.Add("https://graph.microsoft.com/User.Read");

            // The tokens are not written into the authentication cookie. They are captured below
            // and kept encrypted server-side, so a stolen cookie is not a stolen refresh token.
            oidc.SaveTokens = false;

            oidc.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            oidc.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;

            oidc.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = async context =>
                {
                    var refreshToken = context.TokenEndpointResponse?.RefreshToken;
                    var subjectId = ResolveSubjectId(context.Principal);

                    if (string.IsNullOrEmpty(refreshToken) || subjectId is null)
                    {
                        // Without this the user consents, the flow appears to succeed, and every
                        // later Graph call fails for reasons nothing in the sign-in explains.
                        LoggerFor(context.HttpContext).LogWarning(
                            "The Microsoft sign-in returned no refresh token (subject {HasSubject}). " +
                            "Check that offline_access is granted on the app registration.",
                            subjectId is null ? "missing" : "present");

                        return;
                    }

                    var store = context.HttpContext.RequestServices
                        .GetRequiredService<IEntraRefreshTokenStore>();

                    await store.SetAsync(subjectId, refreshToken, context.HttpContext.RequestAborted);

                    LoggerFor(context.HttpContext).LogInformation(
                        "Stored delegated Microsoft access for {Subject}", subjectId);
                },

                OnAuthenticationFailed = context =>
                {
                    LoggerFor(context.HttpContext).LogWarning(
                        "Microsoft sign-in failed: {Reason}", context.Exception.GetType().Name);

                    return Task.CompletedTask;
                },

                // Without this, a misconfiguration surfaces as an unhandled exception page with a
                // stack trace, which buries the one line that says what is wrong. These failures
                // are nearly always configuration rather than defects, so they get a plain answer.
                OnRemoteFailure = context =>
                {
                    var message = context.Failure?.Message ?? "The Microsoft sign-in failed.";

                    LoggerFor(context.HttpContext).LogError(
                        context.Failure, "Microsoft sign-in could not be completed");

                    var guidance = message.Contains("AADSTS7000215", StringComparison.Ordinal)
                        ? "The client secret this server presented was rejected. Check that " +
                          "OneDrive:OboClientSecret holds the secret VALUE from the app " +
                          "registration -- not the secret ID -- and that it has not been deleted " +
                          "or expired."
                        : message.Contains("AADSTS650057", StringComparison.Ordinal)
                          || message.Contains("AADSTS500011", StringComparison.Ordinal)
                            ? "Microsoft did not recognise this application. Check Auth:TenantId " +
                              "and Auth:Audience match the app registration."
                            : "Check the tenant, client id, client secret and redirect URI " +
                              "against the app registration.";

                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    context.Response.ContentType = "application/json";

                    context.HandleResponse();

                    return context.Response.WriteAsJsonAsync(new
                    {
                        error = "sign_in_failed",
                        error_description = guidance,
                        detail = message
                    });
                }
            };
        });
    }

    /// <summary>Reads the <c>iss</c> claim without validating the token.</summary>
    private static string? PeekIssuer(string token)
    {
        try
        {
            var handler = new JsonWebTokenHandler();

            return handler.CanReadToken(token) ? handler.ReadJsonWebToken(token).Issuer : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the user's stable identifier from a signed-in principal.
    /// </summary>
    /// <remarks>
    /// Must agree with the claim the authorization endpoint puts in the <c>sub</c> of the tokens
    /// it issues, because that is the key the stored refresh token is looked up by. If the two
    /// disagree, consent succeeds and every later Graph call reports that no access is held.
    /// </remarks>
    private static string? ResolveSubjectId(System.Security.Claims.ClaimsPrincipal? principal) =>
        principal?.FindFirst("oid")?.Value
        ?? principal?.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
        ?? principal?.FindFirst("sub")?.Value;

    private static ILogger LoggerFor(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(EntraAuthenticationExtensions));

    private static string? StripScheme(string? audience) =>
        audience?.StartsWith("api://", StringComparison.OrdinalIgnoreCase) == true
            ? audience["api://".Length..]
            : null;
}
