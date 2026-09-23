# Creating the Entra app registration

You need this only if you want real authentication. To try the tools against your own drive, skip
it entirely — `scripts/run-local.ps1` takes a Graph Explorer token and needs no registration at
all.

**One registration covers everything.** It is tempting to create two — one "API", one "client" —
because the server plays both roles: it validates inbound tokens *and* signs users in to Microsoft.
Two registrations will not work, because the server derives its OIDC client id from
`Auth:Audience` by stripping `api://`. The audience and the sign-in client are the same
application by construction.

You need the **Application Administrator** role, or someone who has it.

## 1. Register the application

[Entra admin centre](https://entra.microsoft.com) → **App registrations** → **New registration**.

| Field | Value |
|---|---|
| Name | `OneDrive MCP` (any name; users see this on the Microsoft sign-in page) |
| Supported account types | **Accounts in this organizational directory only** (single tenant) |
| Redirect URI | **Web** → `http://localhost:5170/signin-oidc` |

That path is not arbitrary and not configurable — `/signin-oidc` is the ASP.NET Core default and
the server does not override it. Getting it wrong produces `AADSTS50011`, which names the URI
Entra expected, so the error tells you the fix.

When you deploy, add a second redirect URI `https://<your-host>/signin-oidc` to the same
registration. Keep the localhost one so you can still run locally.

From **Overview**, copy the **Application (client) ID** and the **Directory (tenant) ID**.

## 2. Set the Application ID URI

**Expose an API** → **Application ID URI** → **Add**. Accept the default `api://<client-id>`.

This is what inbound access tokens are validated against. Without it there is nothing sensible to
put in `Auth:Audience`.

While you are there, **Add a scope**:

| Field | Value |
|---|---|
| Scope name | `onedrive:access` |
| Who can consent | **Admins and users** |
| Display name / description | anything meaningful |

The name must match `Auth:RequiredScope`, which defaults to `onedrive:access`. This scope is what
a caller presenting a genuine Entra token must hold. Clients that go through the server's own
authorization server get it issued automatically, so if you only ever use that path you can leave
the default alone and never think about it again.

## 3. Add the Graph permissions

**API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**:

- `Files.ReadWrite`
- `User.Read`
- `openid`
- `profile`
- `offline_access`

**Delegated, not Application.** Application permissions would grant this server access to every
drive in the tenant independently of who is asking, which is precisely the design this server
avoids. If you find yourself in the Application list, you are in the wrong place.

`offline_access` is the one people skip, and it is load-bearing: without it Entra issues no refresh
token, so there is nothing to store and the token bridge cannot work. See
[authorization-server.md](authorization-server.md#two-kinds-of-caller-token-two-routes-to-graph).

**Grant admin consent** if you can. Without it each user consents individually on first sign-in,
which works but is a worse first run.

## 4. Create a client secret

**Certificates & secrets** → **New client secret**. Choose the shortest expiry you can live with,
then copy the **Value** column — not **Secret ID**. The value is shown once and never again.

Secrets expire. When yours does, sign-in fails with `AADSTS7000222` and nothing else changes, so
it reads like a server fault rather than a calendar event. Put the expiry date somewhere you will
see it.

## 5. Wire it up

Four values from the four steps above:

| Config key | Where it came from |
|---|---|
| `Auth:TenantId` | Directory (tenant) ID, step 1 |
| `Auth:Audience` | `api://<client-id>`, step 2 |
| `OneDrive:OboTenantId` | same tenant id |
| `OneDrive:OboClientId` | Application (client) ID, step 1 |
| `OneDrive:OboClientSecret` | the secret **Value**, step 4 |

Locally, store them once in .NET user secrets rather than typing them per run — they live in your
Windows profile, outside the repository:

```powershell
.\scripts\set-secrets.ps1
.\scripts\run-local-oauth.ps1
```

Deployed, the secret belongs in Key Vault and the app setting should be a reference
(`@Microsoft.KeyVault(SecretUri=...)`), never a literal. The other four are not secret — a tenant
id and a client id are identifiers, not credentials — but there is no reason to publish them
either.

You will also want, for a deployment:

```jsonc
"Auth": { "EnableOAuth": true, "PublicBaseUrl": "https://<your-host>" },
"OAuthServer": {
  "Enabled": true,
  "Issuer": "https://<your-host>",     // unique per deployment
  "PublicBaseUrl": "https://<your-host>",
  "KeyVaultUri": "https://<vault>.vault.azure.net/",
  "RegistrationInitialAccessToken": "<any long random string>"
}
```

The reasoning behind those four is in
[authorization-server.md](authorization-server.md#four-things-that-will-bite-you) — worth reading
before you deploy rather than after.

## When it does not work

| Symptom | Cause |
|---|---|
| `AADSTS50011` redirect URI mismatch | The URI on the registration does not match exactly. It is case- and trailing-slash-sensitive, and it must end `/signin-oidc`. |
| `AADSTS7000222` | The client secret expired. Create a new one; the app itself is fine. |
| `AADSTS65001` consent required | Admin consent was not granted and the user declined, or `offline_access` is missing. |
| `401` from `/mcp` with `WWW-Authenticate: Bearer` | Working as intended — that header tells the client where to sign in. |
| Tools return `AUTHENTICATION_REQUIRED` | No stored Entra refresh token for this user, or it expired. Sign in again. Check `onedrive_auth_status` first. |
| Everything works except reading file content | Almost certainly tenant policy, not this server. Run `scripts/diagnose-download.ps1`. |
