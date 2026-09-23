<#
.SYNOPSIS
    Runs the OneDrive MCP server locally against a real drive.

.DESCRIPTION
    Starts the server with a Graph token pasted from Graph Explorer, which exercises the whole
    tool surface without any OAuth setup. The token is passed through the environment and is
    never written to disk.

    Authentication is off in this mode and every caller is served as the owner of that token, so
    the server binds to localhost only. Do not expose it.

.PARAMETER GraphToken
    An access token from https://developer.microsoft.com/graph/graph-explorer with the
    Files.ReadWrite and User.Read permissions consented. Prompted for if omitted.

.PARAMETER Port
    Port to listen on. Defaults to 5170.

.EXAMPLE
    .\scripts\run-local.ps1
#>
[CmdletBinding()]
param(
    [string] $GraphToken,
    [int] $Port = 5170
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($GraphToken)) {
    Write-Host ''
    Write-Host 'A Microsoft Graph access token is needed.' -ForegroundColor Cyan
    Write-Host '  1. Open https://developer.microsoft.com/graph/graph-explorer'
    Write-Host '  2. Sign in with the account whose OneDrive you want to test against'
    Write-Host '  3. Under "Modify permissions", consent to Files.ReadWrite and User.Read'
    Write-Host '  4. Open the "Access token" tab and copy the token'
    Write-Host ''

    $secure = Read-Host -Prompt 'Paste the access token' -AsSecureString
    $GraphToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

if ([string]::IsNullOrWhiteSpace($GraphToken)) {
    throw 'No token supplied.'
}

# Graph tokens are JWTs. Catching an obviously wrong paste here is friendlier than a 401 later.
if (($GraphToken -split '\.').Count -ne 3) {
    Write-Warning 'That does not look like a JWT. Check you copied the access token, not the request URL.'
}

$env:Dev__GraphAccessToken = $GraphToken
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:ASPNETCORE_URLS = "http://localhost:$Port"

Write-Host ''
Write-Host "Starting the OneDrive MCP server on http://localhost:$Port" -ForegroundColor Green
Write-Host 'Every caller is served as the owner of that token. Localhost only.' -ForegroundColor Yellow
Write-Host ''
Write-Host 'To exercise it, in another terminal run:' -ForegroundColor Cyan
Write-Host "  .\scripts\smoke-test.ps1"
Write-Host 'or connect a client with:'
Write-Host "  npx @modelcontextprotocol/inspector      (then open http://localhost:$Port/mcp)"
Write-Host ''

try {
    dotnet run --project (Join-Path $repoRoot 'src/OneDriveMcp.Server')
}
finally {
    # Do not leave a live credential in the shell after the server stops.
    Remove-Item Env:\Dev__GraphAccessToken -ErrorAction SilentlyContinue
}
