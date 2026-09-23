using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using OneDriveMcp.Server.OAuth.Configuration;
using OneDriveMcp.Server.OAuth.Services;

namespace OneDriveMcp.Server.OAuth.Endpoints;

/// <summary>
/// The authorization endpoint, and the consent step it leads to.
/// </summary>
/// <remarks>
/// The user is authenticated by Entra through an interactive OpenID Connect sign-in, and this
/// server then issues its own authorization code. Entra establishes <em>who</em> the user is;
/// this server decides what the MCP client is allowed to do.
/// </remarks>
public static class AuthorizeEndpoint
{
    /// <summary>Maps the authorization and consent endpoints.</summary>
    public static IEndpointRouteBuilder MapOAuthAuthorize(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet("/oauth/authorize", async (
            HttpContext context,
            IOptions<OAuthServerOptions> options,
            IOAuthClientStore clientStore,
            ConsentSessionStore consentStore) =>
        {
            var query = context.Request.Query;

            var responseType = query["response_type"].ToString();
            var clientId = query["client_id"].ToString();
            var redirectUri = query["redirect_uri"].ToString();
            var codeChallenge = query["code_challenge"].ToString();
            var codeChallengeMethod = query["code_challenge_method"].ToString();
            var state = query["state"].ToString();
            var scope = query["scope"].ToString();

            if (!string.Equals(responseType, "code", StringComparison.Ordinal))
            {
                return Invalid("unsupported_response_type", "Only the authorization code flow is supported.");
            }

            var client = clientStore.Find(clientId);

            if (client is null)
            {
                return Invalid("invalid_client", "Unknown client_id.");
            }

            // Matched exactly against the registration. This is what stops an attacker who knows
            // a client id from having the code delivered to an address of their choosing.
            if (!client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
            {
                return Invalid("invalid_request", "redirect_uri does not match a registered URI.");
            }

            if (string.IsNullOrEmpty(codeChallenge))
            {
                return Invalid("invalid_request", "code_challenge is required; PKCE is mandatory.");
            }

            // S256 only. Plain PKCE gives no protection against someone who can observe the
            // authorization request, which is the threat it exists to address.
            if (!string.Equals(codeChallengeMethod, "S256", StringComparison.Ordinal))
            {
                return Invalid("invalid_request", "code_challenge_method must be S256.");
            }

            var user = context.User;

            if (user?.Identity?.IsAuthenticated != true)
            {
                // Send the user to Entra, returning here afterwards with the same query string so
                // the authorization request resumes exactly where it left off.
                var returnUrl = $"{context.Request.Path}{context.Request.QueryString}";

                return Results.Challenge(
                    new AuthenticationProperties { RedirectUri = returnUrl },
                    [OpenIdConnectDefaults.AuthenticationScheme]);
            }

            var subjectId = ResolveSubject(user);

            if (subjectId is null)
            {
                // Without a stable identifier there is nothing to bind the grant to, and falling
                // back to a generated one would silently create a new identity on every sign-in.
                return Invalid(
                    "server_error",
                    "The signed-in account has no stable identifier (oid or sub) to authorize against.");
            }

            var session = new ConsentSession(
                subjectId,
                clientId,
                redirectUri,
                codeChallenge,
                string.IsNullOrWhiteSpace(scope) ? options.Value.Scope : scope,
                string.IsNullOrEmpty(state) ? null : state,
                user.FindFirst(ClaimTypes.Email)?.Value ?? user.FindFirst("preferred_username")?.Value);

            var csrfToken = consentStore.Create(session);

            // Paired with the log on the consent post, so the two subjects can be compared. They
            // come from different places -- this one from the sign-in just completed, the other
            // from the cookie on the next request -- and a mismatch is otherwise invisible.
            context.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(AuthorizeEndpoint))
                .LogInformation(
                    "Consent page shown to {Subject} for client {ClientId}, token {Token}",
                    subjectId, clientId, ConsentSessionStore.Describe(csrfToken));

            return RenderConsentPage(
                context, client.ClientName, csrfToken, session.RedirectUri, session.Email);
        })
        .WithName("OAuthAuthorize")
        .AllowAnonymous();

        endpoints.MapPost("/oauth/authorize/consent", async (
            HttpContext context,
            ConsentSessionStore consentStore,
            OAuthTokenService tokenService) =>
        {
            var user = context.User;

            if (user?.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }

            var subjectId = ResolveSubject(user);

            if (subjectId is null)
            {
                return Invalid("server_error", "The signed-in account has no stable identifier.");
            }

            if (!context.Request.HasFormContentType)
            {
                return Invalid("invalid_request", "Expected a form-encoded body.");
            }

            var form = await context.Request.ReadFormAsync();

            // Everything security-relevant comes from the stored session, never the form. The
            // form supplies only the token and the yes-or-no answer.
            var session = consentStore.Consume(
                form["csrf_token"].ToString(), subjectId, out var failure);

            if (session is null)
            {
                var logger = context.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger(typeof(AuthorizeEndpoint));

                var presented = form["csrf_token"].ToString();

                // Logged with the reason because the three cases are not the same event: an
                // expired session is routine, a subject mismatch is somebody posting a form that
                // was issued to a different account. Whether this process ever issued the token
                // separates "expired here" from "issued by a process that has since restarted",
                // which otherwise look identical.
                logger.LogWarning(
                    "Consent could not be completed for {Subject}: {Reason}. " +
                    "Token {Token} was issued by this instance: {IssuedHere}. " +
                    "This instance has issued {IssuedCount} consent token(s) since it started.",
                    subjectId,
                    failure,
                    ConsentSessionStore.Describe(presented),
                    consentStore.WasIssuedHere(presented),
                    consentStore.IssuedCount);

                var description = failure switch
                {
                    ConsentSessionStore.ConsentFailure.MissingToken =>
                        "The consent form did not include its verification token.",

                    ConsentSessionStore.ConsentFailure.SubjectMismatch =>
                        "This consent form was issued to a different account than the one now " +
                        "signed in. Sign out and start again.",

                    // Also covers a server restart, because consent sessions are held in memory.
                    _ => "This consent request has expired or was already used. Start the " +
                         "sign-in again."
                };

                return Invalid("invalid_request", description);
            }

            if (!string.Equals(form["approve"].ToString(), "true", StringComparison.Ordinal))
            {
                return Results.Redirect(BuildRedirect(
                    session.RedirectUri,
                    ("error", "access_denied"),
                    ("state", session.State)));
            }

            var code = tokenService.IssueAuthorizationCode(
                session.ClientId,
                session.RedirectUri,
                session.CodeChallenge,
                session.SubjectId,
                session.Email,
                session.Scope);

            // Logged so a later refusal of the same token is recognisable as a resubmission of a
            // form that already worked, rather than a first attempt that failed.
            context.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(AuthorizeEndpoint))
                .LogInformation(
                    "Consent granted by {Subject} for client {ClientId}; authorization code issued",
                    session.SubjectId, session.ClientId);

            return Results.Redirect(BuildRedirect(
                session.RedirectUri,
                ("code", code),
                ("state", session.State)));
        })
        .WithName("OAuthConsent")
        .AllowAnonymous();

        return endpoints;
    }

    /// <summary>
    /// Resolves the user's stable identifier.
    /// </summary>
    /// <remarks>
    /// <c>oid</c> is preferred: it is stable for the user across applications, whereas <c>sub</c>
    /// is only unique per (user, application) pair. The rest of the server keys the Graph token
    /// cache on the same claim, so they have to agree.
    /// </remarks>
    private static string? ResolveSubject(ClaimsPrincipal user) =>
        user.FindFirst("oid")?.Value
        ?? user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value
        ?? user.FindFirst("sub")?.Value
        ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    private static string BuildRedirect(string redirectUri, params (string Key, string? Value)[] parameters)
    {
        var separator = redirectUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        var query = string.Join('&', parameters
            .Where(p => !string.IsNullOrEmpty(p.Value))
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value!)}"));

        return query.Length == 0 ? redirectUri : $"{redirectUri}{separator}{query}";
    }

    private static IResult Invalid(string error, string description) =>
        Results.BadRequest(new { error, error_description = description });

    /// <summary>
    /// Renders the consent page.
    /// </summary>
    /// <remarks>
    /// This is the one response that is markup, so it needs its own Content-Security-Policy rather
    /// than the deny-everything default the rest of the server uses. Every interpolated value is
    /// HTML-encoded: the client name in particular is attacker-supplied, straight from a
    /// self-service registration.
    /// </remarks>
    /// <summary>
    /// Builds the Content-Security-Policy for the consent page.
    /// </summary>
    /// <param name="redirectUri">
    /// The client's registered redirect URI, already matched against the registration before the
    /// page is rendered, so it is not caller-supplied at this point.
    /// </param>
    /// <remarks>
    /// <para>
    /// <c>form-action</c> governs where a submission may end up, and browsers apply it to the
    /// redirect that <em>follows</em> the post, not only its immediate target. Granting consent
    /// redirects to the client's address, which is a different origin, so <c>'self'</c> alone
    /// silently blocks the hand-back: the server issues an authorization code, returns a correct
    /// 302, and the browser refuses to deliver it. The client waits forever and nothing in any
    /// server log suggests a problem, because from the server's side everything succeeded.
    /// </para>
    /// <para>
    /// The client's origin is added rather than the directive being dropped, so a page-injection
    /// attempt still cannot post a form anywhere it likes.
    /// </para>
    /// </remarks>
    internal static string BuildConsentCsp(string? redirectUri)
    {
        var formAction = "'self'";

        if (Uri.TryCreate(redirectUri, UriKind.Absolute, out var redirect)
            && (redirect.Scheme == Uri.UriSchemeHttps || redirect.Scheme == Uri.UriSchemeHttp))
        {
            formAction = $"'self' {redirect.Scheme}://{redirect.Authority}";
        }

        return $"default-src 'none'; style-src 'unsafe-inline'; form-action {formAction}; " +
               "frame-ancestors 'none'";
    }

    /// <summary>
    /// Renders the consent page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The only page a person ever sees from this server, and the moment they decide whether to
    /// hand an application access to their files -- so it has to look like something worth
    /// trusting. It names the application, the account being used, and what is actually being
    /// granted, rather than asking for a blank cheque.
    /// </para>
    /// <para>
    /// Everything is inline. The Content-Security-Policy allows no scripts and no external
    /// resources, so there are no web fonts, no icon libraries and no stylesheets: the icons are
    /// inline SVG, which is markup rather than a fetch, and the type stack falls back to whatever
    /// the operating system provides. That also means the page renders instantly and works with
    /// the network disconnected.
    /// </para>
    /// <para>
    /// Every interpolated value is HTML-encoded. The application name in particular arrives from
    /// self-service registration and is entirely attacker-controlled.
    /// </para>
    /// </remarks>
    private static IResult RenderConsentPage(
        HttpContext context,
        string? clientName,
        string csrfToken,
        string redirectUri,
        string? account)
    {
        context.Response.Headers.ContentSecurityPolicy = BuildConsentCsp(redirectUri);

        // This page carries a single-use token and reflects the current sign-in, so it must never
        // be served from a cache or restored from the back-forward cache. A stale copy posts a
        // token that no longer exists, which surfaces as "this consent request has expired" on
        // what looks to the user like a first attempt.
        context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        context.Response.Headers.Pragma = "no-cache";
        context.Response.Headers.Expires = "0";

        var safeClientName = WebUtility.HtmlEncode(
            string.IsNullOrWhiteSpace(clientName) ? "An application" : clientName);
        var safeToken = WebUtility.HtmlEncode(csrfToken);

        var accountRow = string.IsNullOrWhiteSpace(account)
            ? string.Empty
            : $"""
                     <div class="account">
                       <svg class="avatar" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10Zm0 2c-5 0-9 2.5-9 5.5V21h18v-1.5c0-3-4-5.5-9-5.5Z"/></svg>
                       <div class="account-text">
                         <span class="account-label">Signed in as</span>
                         <span class="account-name">{WebUtility.HtmlEncode(account)}</span>
                       </div>
                     </div>
               """;

        var html = $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <meta name="robots" content="noindex, nofollow">
              <title>Authorize access to OneDrive</title>
              <style>
                /* One accent, everything else neutral. Both themes are defined up front so the
                   page follows the operating system rather than assuming light. */
                :root {
                  --bg: #f4f5f7;
                  --surface: #ffffff;
                  --border: #e3e5e8;
                  --text: #16181d;
                  --text-muted: #5c6270;
                  --accent: #0f6cbd;
                  --accent-hover: #0c5697;
                  --accent-contrast: #ffffff;
                  --focus: #0f6cbd;
                  --shadow: 0 1px 2px rgba(16, 24, 40, .04), 0 8px 24px rgba(16, 24, 40, .08);
                }

                @media (prefers-color-scheme: dark) {
                  :root {
                    --bg: #16181d;
                    --surface: #1e2128;
                    --border: #2f333c;
                    --text: #f2f3f5;
                    --text-muted: #a0a6b4;
                    --accent: #4da3e8;
                    --accent-hover: #6cb5ee;
                    --accent-contrast: #0b1520;
                    --focus: #4da3e8;
                    --shadow: 0 1px 2px rgba(0, 0, 0, .3), 0 8px 24px rgba(0, 0, 0, .4);
                  }
                }

                * { box-sizing: border-box; }

                body {
                  margin: 0;
                  min-height: 100vh;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  padding: 24px;
                  background: var(--bg);
                  color: var(--text);
                  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                               "Helvetica Neue", Arial, sans-serif;
                  font-size: 16px;
                  line-height: 1.5;
                  -webkit-font-smoothing: antialiased;
                }

                .card {
                  width: 100%;
                  max-width: 400px;
                  background: var(--surface);
                  border: 1px solid var(--border);
                  border-radius: 14px;
                  box-shadow: var(--shadow);
                  padding: 40px 36px 32px;
                }

                .mark {
                  width: 40px; height: 40px;
                  border-radius: 10px;
                  background: var(--accent);
                  display: flex; align-items: center; justify-content: center;
                  margin-bottom: 24px;
                }
                .mark svg { width: 22px; height: 22px; fill: var(--accent-contrast); }

                h1 {
                  margin: 0 0 8px;
                  font-size: 22px;
                  line-height: 1.3;
                  font-weight: 600;
                  letter-spacing: -.01em;
                }

                .lede { margin: 0 0 24px; color: var(--text-muted); }
                .lede strong { color: var(--text); font-weight: 600; }

                .account {
                  display: flex; align-items: center; gap: 12px;
                  padding: 12px 14px;
                  margin-bottom: 28px;
                  background: var(--bg);
                  border: 1px solid var(--border);
                  border-radius: 10px;
                }
                .avatar { width: 20px; height: 20px; fill: var(--text-muted); flex: none; }
                .account-text { display: flex; flex-direction: column; min-width: 0; }
                .account-label { font-size: 12px; color: var(--text-muted); }
                .account-name {
                  font-size: 14px; font-weight: 500;
                  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                }

                .actions { display: flex; gap: 10px; }

                button {
                  flex: 1;
                  font: inherit; font-weight: 500;
                  padding: 11px 16px;
                  border-radius: 8px;
                  border: 1px solid transparent;
                  cursor: pointer;
                  transition: background-color .15s ease, border-color .15s ease;
                }
                button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

                .approve { background: var(--accent); color: var(--accent-contrast); }
                .approve:hover { background: var(--accent-hover); }

                .deny { background: transparent; color: var(--text); border-color: var(--border); }
                .deny:hover { border-color: var(--text-muted); }

                /* Stack the buttons before they get too narrow to read. */
                @media (max-width: 420px) {
                  .card { padding: 28px 22px 24px; border-radius: 12px; }
                  .actions { flex-direction: column-reverse; }
                }

                @media (prefers-reduced-motion: reduce) {
                  * { transition: none !important; }
                }
              </style>
            </head>
            <body>
              <main class="card">
                <div class="mark" aria-hidden="true">
                  <svg viewBox="0 0 24 24"><path d="M6.5 19q-2.3 0-3.9-1.6T1 13.5q0-2 1.2-3.5t3.1-1.9q.6-2.3 2.4-3.7T12 3q2.8 0 4.7 2t1.9 4.7v.5q1.9.2 3.1 1.6t1.3 3.3q0 2-1.4 3.4T18.2 19H6.5Z"/></svg>
                </div>

                <h1>Allow access to your OneDrive?</h1>
                <p class="lede"><strong>{{safeClientName}}</strong> is asking to work with your files on your behalf.</p>

            {{accountRow}}

                <form method="post" action="/oauth/authorize/consent">
                  <input type="hidden" name="csrf_token" value="{{safeToken}}">
                  <div class="actions">
                    <button class="deny" type="submit" name="approve" value="false">Cancel</button>
                    <button class="approve" type="submit" name="approve" value="true">Allow access</button>
                  </div>
                </form>

              </main>
            </body>
            </html>
            """;

        return Results.Content(html, "text/html; charset=utf-8");
    }
}
