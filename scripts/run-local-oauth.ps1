<#
.SYNOPSIS
    Runs the OneDrive MCP server locally with real authentication and the built-in authorization
    server, so the whole sign-in flow can be exercised without deploying anything.

.DESCRIPTION
    Needs one Entra application registration, which is a directory object rather than a
    deployment -- no Azure resources are created and nothing is hosted. Everything runs on
    localhost.

    Create the registration by hand in the tenant that owns the OneDrive account:
    Entra admin centre > App registrations > New registration, with a Web redirect URI of
    http://localhost:5170/signin-oidc. Under API permissions add the DELEGATED Microsoft Graph
    permissions Files.ReadWrite, User.Read, openid, profile and offline_access, then grant
    consent. Under Certificates & secrets create a client secret and copy the VALUE, not the
    Secret ID. The tenant id, application (client) id and that secret are the three values this
    script wants; scripts/set-secrets.ps1 will store them so you need type them only once.

    Signing keys are held in memory in this mode, so restarting the server invalidates any token
    it has issued. That is fine for testing and is why a deployment needs Key Vault.

.PARAMETER TenantId
    The Entra tenant that owns the OneDrive account.

.PARAMETER ClientId
    Application (client) id of the registration.

.PARAMETER ClientSecret
    A client secret for that registration. Prompted for if omitted.

.PARAMETER Port
    Port to listen on. Must match the redirect URI on the registration. Defaults to 5170.

.EXAMPLE
    .\scripts\run-local-oauth.ps1 -TenantId <guid> -ClientId <guid>
#>
[CmdletBinding()]
param(
    [string] $TenantId,
    [string] $ClientId,
    [string] $ClientSecret,
    [int] $Port = 5170
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repoRoot 'src/OneDriveMcp.Server'

# Anything already in user secrets fills the gaps, so a configured machine needs no arguments.
# ASP.NET Core reads them itself in Development; they are read here only to show what is in use
# and to decide whether the secret still has to be asked for.
$stored = @{}

try {
    foreach ($line in (dotnet user-secrets list --project $project 2>$null)) {
        if ($line -match '^(?<key>[^=]+)=\s*(?<value>.*)$') {
            $stored[$Matches['key'].Trim()] = $Matches['value'].Trim()
        }
    }
}
catch {
    # No secrets set yet, which is fine -- the prompts below cover it.
}

if ([string]::IsNullOrWhiteSpace($TenantId)) { $TenantId = $stored['OneDrive:OboTenantId'] }
if ([string]::IsNullOrWhiteSpace($ClientId)) { $ClientId = $stored['OneDrive:OboClientId'] }

$secretFromStore = -not [string]::IsNullOrWhiteSpace($stored['OneDrive:OboClientSecret'])

if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId)) {
    throw 'No tenant or client id. Pass -TenantId and -ClientId, or store them once with ' +
          'scripts/set-secrets.ps1.'
}

if ([string]::IsNullOrWhiteSpace($ClientSecret) -and -not $secretFromStore) {
    Write-Host 'No client secret in user secrets. Store it once with scripts/set-secrets.ps1' -ForegroundColor DarkGray
    Write-Host 'to stop being asked.' -ForegroundColor DarkGray
    Write-Host ''

    $secure = Read-Host -Prompt 'Paste the client secret' -AsSecureString
    $ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))

    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { throw 'No client secret supplied.' }
}

$baseUrl = "http://localhost:$Port"

# Entra permits plain HTTP redirect URIs for loopback addresses specifically, which is what makes
# this work without a certificate. Browsers also treat localhost as a secure context, so the
# Secure cookies the consent flow sets are accepted.
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:ASPNETCORE_URLS = $baseUrl

$env:Auth__EnableOAuth = 'true'
$env:Auth__TenantId = $TenantId
$env:Auth__Audience = "api://$ClientId"
$env:Auth__PublicBaseUrl = $baseUrl

$env:OAuthServer__Enabled = 'true'
$env:OAuthServer__Issuer = $baseUrl
$env:OAuthServer__PublicBaseUrl = $baseUrl

$env:OneDrive__OboTenantId = $TenantId
$env:OneDrive__OboClientId = $ClientId

# Only set when it came from an argument or a prompt. Leaving it unset lets the value in user
# secrets apply, which keeps the secret out of this process's environment entirely.
if (-not [string]::IsNullOrWhiteSpace($ClientSecret)) {
    $env:OneDrive__OboClientSecret = $ClientSecret
}

# Keep the refresh-token store out of the build output during testing so a run leaves nothing
# behind; the empty value disables persistence entirely.
$env:OAuthServer__EntraTokenPath = ''

# Ensure the development shortcut is off, or every caller would be served as one user and none of
# the authentication being tested here would come into play.
Remove-Item Env:\Dev__GraphAccessToken -ErrorAction SilentlyContinue

Write-Host ''
Write-Host "Starting with authentication ON at $baseUrl" -ForegroundColor Green
Write-Host ''
Write-Host "  tenant   $TenantId"
Write-Host "  client   $ClientId"
Write-Host "  audience api://$ClientId"

if ($secretFromStore -and [string]::IsNullOrWhiteSpace($ClientSecret)) {
    Write-Host "  secret   from user secrets" -ForegroundColor DarkGray
}
else {
    Write-Host "  secret   supplied for this run" -ForegroundColor DarkGray
}
Write-Host ''
Write-Host 'The registration needs this redirect URI:' -ForegroundColor Cyan
Write-Host "  $baseUrl/signin-oidc"
Write-Host ''
Write-Host 'Try it with:' -ForegroundColor Cyan
Write-Host "  curl $baseUrl/.well-known/oauth-authorization-server"
Write-Host "  curl -i -X POST $baseUrl/mcp        # expect 401 with a WWW-Authenticate challenge"
Write-Host "  npx @modelcontextprotocol/inspector  # then connect to $baseUrl/mcp"
Write-Host ''
Write-Host 'Inspector will register itself, send you through the Microsoft sign-in, show the' -ForegroundColor DarkGray
Write-Host 'consent page, and come back with a token. That exercises the whole flow.' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Token signing keys are in memory only, so restarting invalidates issued tokens.' -ForegroundColor Yellow
Write-Host ''

try {
    dotnet run --project (Join-Path $repoRoot 'src/OneDriveMcp.Server')
}
finally {
    foreach ($name in @(
        'Auth__EnableOAuth', 'Auth__TenantId', 'Auth__Audience', 'Auth__PublicBaseUrl',
        'OAuthServer__Enabled', 'OAuthServer__Issuer', 'OAuthServer__PublicBaseUrl',
        'OAuthServer__EntraTokenPath',
        'OneDrive__OboTenantId', 'OneDrive__OboClientId', 'OneDrive__OboClientSecret')) {
        Remove-Item "Env:\$name" -ErrorAction SilentlyContinue
    }
}
