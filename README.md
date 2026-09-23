# OneDrive MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server for Microsoft OneDrive. It
gives an MCP client — Claude, MCP Inspector, VS Code — delegated access to the signed-in user's
own OneDrive through Microsoft Graph.

Every caller acts strictly as themselves. The server exchanges each caller's token for a Graph
token through the on-behalf-of flow, so it can only ever see the drive of the person making the
request. There is no service account and no app-only access.

Built on .NET 10. 16 tools, 320 tests.

## Quickstart

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
git clone https://github.com/lakshitha-dev/onedrive-mcp.git
cd onedrive-mcp
dotnet test
```

To try it against a real drive without setting up any Azure resources, paste a token from
[Graph Explorer](https://developer.microsoft.com/graph/graph-explorer) — sign in as the account
whose OneDrive you want, consent to `Files.ReadWrite` and `User.Read` under **Modify
permissions**, then copy the **Access token** tab:

```powershell
.\scripts\run-local.ps1     # prompts for the token, starts on http://localhost:5170
.\scripts\smoke-test.ps1    # in a second terminal — exercises every tool, then cleans up
```

The token is passed through the environment and never written to disk.

## Connect a client

**Claude Code**

```bash
claude mcp add --transport http onedrive http://localhost:5170/mcp
```

**MCP Inspector**

```bash
npx @modelcontextprotocol/inspector
# connect to http://localhost:5170/mcp
```

**By hand.** The 2026-07-28 protocol revision is stateless — there is no `initialize` handshake
and no session id — so a single request needs the protocol version, the method, the tool name, and
the version plus client capabilities in `params._meta`:

```bash
curl -s -X POST http://localhost:5170/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: onedrive_list_files' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"onedrive_list_files","arguments":{},
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                 "io.modelcontextprotocol/clientCapabilities":{}}}}'
```

## Tools

Every tool acting on an existing item takes either `path` (relative to the drive root) or
`itemId` — never both. Ids are what search and recent return, and are the only way to reach an
item on another drive.

**Browse and read**

| Tool | Notes |
|---|---|
| `onedrive_list_files` | Folder contents. Paged via `nextCursor`. |
| `onedrive_get_item` | Metadata for one file or folder. |
| `onedrive_read_text_file` | UTF-8 text, truncated at `MaxTextFileReadBytes`. |
| `onedrive_get_download_url` | Temporary direct URL. **Disabled by default.** |
| `onedrive_get_drive_info` | Drive type, owner, quota. |

**Write and organise**

| Tool | Notes |
|---|---|
| `onedrive_upload_file` | `encoding` of `text` or `base64`. Defaults to `conflictBehavior: rename`, so nothing is silently overwritten. Switches to a resumable session above 4 MB. |
| `onedrive_create_folder` | Parent folders are created automatically. |
| `onedrive_delete_item` | To the recycle bin. Requires an explicit target — there is no drive-root default. |
| `onedrive_move_item` | Move and rename in one call, as Graph does. |
| `onedrive_copy_item` | Asynchronous in Graph; may return `status: inProgress`. |

**Search**

| Tool | Notes |
|---|---|
| `onedrive_search` | Names and, for supported formats, contents. |
| `onedrive_list_recent` | Recently used files. |

**Sharing**

| Tool | Notes |
|---|---|
| `onedrive_create_share_link` | Defaults to `organization` scope with an expiry always set. Anonymous links **disabled by default**. |
| `onedrive_list_permissions` | Who currently has access. |
| `onedrive_delete_permission` | Revokes a permission, which is how a link is withdrawn. |

Plus `onedrive_auth_status`, which reports how the caller is authenticated without touching Graph.

## Authentication

Authentication is **off by default**, so the server runs locally with no setup. The host refuses
to start in Production without it.

```jsonc
"Auth": {
  "EnableOAuth": true,
  "TenantId": "<tenant guid>",
  "Audience": "api://<client guid>",      // this server's Application ID URI
  "PublicBaseUrl": "https://<host>"       // advertised in the resource metadata
},
"OneDrive": {
  "OboTenantId": "<tenant guid>",
  "OboClientId": "<client guid>"
  // OboClientSecret belongs in Key Vault, never here
}
```

The Entra app registration needs the **delegated** permissions `Files.ReadWrite`, `User.Read`,
`openid`, `profile` and `offline_access`. Without `offline_access` no refresh token is issued and
every call pays for a fresh token exchange.

With authentication on, an anonymous request to `/mcp` returns `401` with
`WWW-Authenticate: Bearer resource_metadata="..."`, which is how a client discovers where to sign
in. Health endpoints stay anonymous so probes keep working.

The server can also act as **its own OAuth 2.1 authorization server** with Dynamic Client
Registration, so an MCP client can connect without anyone creating an app registration for it by
hand. That is the part most worth reading before deploying:
**[docs/authorization-server.md](docs/authorization-server.md)**.

```powershell
.\scripts\set-secrets.ps1        # store tenant, client id and secret in .NET user secrets
.\scripts\run-local-oauth.ps1    # full sign-in flow, all on localhost
```

## Configuration

Bound from the `OneDrive` section. Secrets belong in Key Vault references
(`@Microsoft.KeyVault(...)`), never in `appsettings.json`.

| Key | Default | Purpose |
|---|---|---|
| `OboTenantId`, `OboClientId`, `OboClientSecret` | — | Entra app used for the on-behalf-of exchange |
| `OboGraphScope` | `Files.ReadWrite User.Read offline_access` | Graph scopes requested |
| `RootPath` | *(empty)* | Confines every path to a prefix. Empty means the whole drive |
| `DeniedPathPrefixes` | `[]` | Path prefixes tools may never touch |
| `AllowDownloadUrls` | `false` | Permits `onedrive_get_download_url` |
| `AllowAnonymousLinks` | `false` | Permits anyone-with-the-link sharing |
| `ShareLinkExpiryDays` | `7` | Default sharing-link lifetime |
| `MaxTextFileReadBytes` | `51200` | Text read cap |
| `MaxFileSizeBytes` | `10485760` | Upload cap |
| `LargeFileThresholdBytes` | `4194304` | Above this, a resumable session is used |
| `MaxBase64UploadBytes` | `3145728` | Decoded base64 cap |
| `MaxConcurrentRequests` | `10` | Concurrent tool executions |
| `DefaultPageSize` / `MaxPageSize` | `50` / `200` | Paging |

## Security

This server addresses the whole drive rather than an app folder, which makes these guards
load-bearing rather than incidental.

- **Path handling.** Every path is traversal-checked — including double-encoded forms like
  `%252E%252E%252F` — and then **percent-encoded per segment**. Without the encoding, a filename
  containing `#`, `%`, `?`, `+` or `:` either breaks Graph addressing or appends OData to the
  request.
- **OData escaping.** Search terms are escaped, so an ordinary name like `O'Brien` cannot
  terminate the query literal.
- **Content URLs.** Pre-authenticated URLs are checked against a Microsoft host allow-list before
  the server fetches them, and are fetched with **no** `Authorization` header — forwarding the
  Graph bearer to a redirect target would hand over access to the whole drive.
- **Pagination cursors** are opaque and re-validated against the Graph host on the way back in.
  Accepting a raw `nextLink` would mean fetching a caller-supplied URL with the caller's token.
- **Destructive tools are annotated.** `Destructive` and `ReadOnly` hints let clients confirm
  before acting. This matters more than usual because a stateless transport cannot prompt the user
  mid-call.
- **Treat file content as untrusted.** Anyone who can drop a file into a shared folder can put
  instructions in front of the model, and the model holds `onedrive_delete_item` and
  `onedrive_create_share_link`.

The smoke test asserts the refusals as well as the successes: path traversal, encoded traversal,
anonymous sharing links, download URLs and a delete with no target all count as passes when they
are rejected.

## Known limitations

**Some tenants block reading file content.** Uploads, folder operations, listing, rename, search
and sharing all succeed, but fetching a file's bytes returns `401`. Graph always redirects content
requests to a SharePoint host, and a tenant can apply Conditional Access or app-enforced
restrictions at that layer which Graph itself does not apply — which is why every other operation
works. No setting on this server changes it.

`scripts/diagnose-download.ps1` talks straight to Graph with this server out of the path, so you
can tell tenant policy apart from a bug. If every route to the bytes fails there too, it is
policy. `onedrive_read_text_file` reports this as `CONTENT_UNAVAILABLE` rather than suggesting a
re-authentication that would not help.

**Stateless transport.** As of the 2026-07-28 revision the transport has no sessions (SEP-2567
removed `Mcp-Session-Id`, SEP-2575 removed the `initialize` handshake). The server therefore needs
no session affinity, but it cannot make requests back to the client — sampling, elicitation and
roots are unavailable.

**One instance.** The built-in authorization server keeps client registrations and in-flight
authorizations in process, so it does not scale out as-is. See
[docs/authorization-server.md](docs/authorization-server.md#scaling).

**`list_shared_with_me` is not implemented.** `Files.ReadWrite` covers only the caller's own
drive, so listing items from other people's drives would return items this server could not then
open. It needs `Files.Read.All`, which is a much broader grant.

## Layout

```
src/OneDriveMcp.Core      Graph client, tools, guards. No ASP.NET dependency, so every tool
                          class is constructible in a unit test.
src/OneDriveMcp.Server    ASP.NET Core host: MCP transport, auth, the tool-call filter.
tests/                    320 tests. Core uses a hand-written HttpMessageHandler fake;
                          Server drives the real host through WebApplicationFactory.
scripts/                  Local run, smoke test, end-to-end OAuth test, single-tool CLI.
```

## Licence

[MIT](LICENSE).
