# The built-in authorization server

Most MCP servers delegate authentication to an existing identity provider and stop there. This
one can act as its own OAuth 2.1 authorization server, and the reason is narrow enough to be
worth stating plainly.

**Entra ID does not support Dynamic Client Registration.** An MCP client that has never seen your
server before has no client id and no way to obtain one, so without DCR somebody has to create an
app registration by hand for every client, in the portal, before that client can connect. That is
the difference between "paste a URL" and "raise a ticket".

So the server registers clients itself, authenticates the user through Entra, and issues its own
tokens.

```jsonc
"OAuthServer": {
  "Enabled": true,
  "Issuer": "https://<host>",            // must be unique to this deployment
  "PublicBaseUrl": "https://<host>",
  "KeyVaultUri": "https://<vault>.vault.azure.net/",
  "RegistrationInitialAccessToken": "<required outside localhost>"
}
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | Discovery metadata (RFC 8414) |
| `GET /.well-known/oauth-protected-resource` | Resource metadata (RFC 9728) |
| `GET /oauth/jwks` | Public signing keys |
| `POST /oauth/register` | Dynamic Client Registration (RFC 7591) |
| `GET /oauth/authorize` | Authorization. PKCE S256 is mandatory |
| `POST /oauth/authorize/consent` | Consent form post |
| `POST /oauth/token` | `authorization_code` and `refresh_token` grants |
| `POST /oauth/revoke` | Revocation (RFC 7009) |

## Four things that will bite you

**`Issuer` must be unique per deployment.** Two deployments sharing one would accept each other's
tokens, so a token minted against a test environment would unlock production. Checked at startup,
because this is not a mistake you want to discover from logs.

**Set `KeyVaultUri` anywhere that is not localhost.** Otherwise the signing key lives only in
memory and every restart invalidates every token the server has issued. The app *writes* the key
back on first use, so its managed identity needs the Key Vault **Secrets Officer** role — not
Secrets User, which is read-only and fails at exactly the wrong moment.

**Set `RegistrationInitialAccessToken`,** or `/oauth/register` is open to anyone who can reach the
server. The host warns about this outside Development but will not stop you.

**Refresh tokens rotate, and reuse revokes the whole family.** A replayed refresh token means
either the legitimate client or an attacker is holding a stale copy, and there is no way to tell
which from the request. Both get cut off and the user signs in again. That is the intended
behaviour, not a bug to work around.

## State that survives a restart

Registered clients, issued refresh tokens and the revocation lists are written to disk,
encrypted with ASP.NET Core Data Protection, and reloaded at startup. `OAuthServer:PersistencePath`
controls where; on Azure App Service it defaults to `/home/data/oauth-state.json`, which is the
durable mount. Set it to an empty string to disable persistence entirely.

Revocation flushes immediately rather than waiting for the periodic save. Losing thirty seconds of
client registrations to a crash is a nuisance; losing a revocation means a token somebody
deliberately killed starts working again after the next restart.

Authorization codes and in-flight consent sessions are deliberately **not** persisted. They live
for minutes, and a restart mid-sign-in costs one retry.

## Two kinds of caller token, two routes to Graph

This is the least obvious part of the design, and worth understanding before you change anything
near it.

The authorization server issues **self-signed JWTs**. Entra rejects a self-signed JWT as an
on-behalf-of assertion — reasonably, since it never issued it. And because this server is
delegated-only, it has no service identity to fall back on: there is no app-only token that could
stand in for the user.

So it bridges. The Entra refresh token captured during the consent sign-in is stored per user,
encrypted at rest, and redeemed for a Graph token whenever that user's requests arrive carrying a
self-issued token. A genuine Entra token skips all of this and goes through on-behalf-of directly.

`onedrive_auth_status` reports which of the two routes a given caller is on, which is the first
thing to check when Graph calls fail for one client and succeed for another.

The bridge needs `offline_access` alongside the Graph scopes on the consent sign-in. Without it
Entra issues no refresh token and there is nothing to store. When a user has no stored access, or
it has expired, tools return `AUTHENTICATION_REQUIRED` and say so — rather than failing in a way
that looks like a permissions problem.

## Scaling

**Single instance.** Registration and authorization are separate requests, and the state that
links them is held in the process that served the first one. Two instances behind a load balancer
means instance B has never heard of the client that registered with instance A. Sticky sessions do
not fix this, because the MCP client and the user's browser are different origins arriving
independently.

Moving to a shared store — Redis, or a table — is the fix if you need to scale out. Nothing else
in the server requires it.
