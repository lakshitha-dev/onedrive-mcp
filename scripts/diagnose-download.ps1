<#
.SYNOPSIS
    Works out why downloading file content returns 401, independently of the MCP server.

.DESCRIPTION
    Talks directly to Microsoft Graph with a token, so the result says whether the problem is in
    this project's code or in how the tenant treats content URLs. Nothing in the OneDrive MCP
    server is involved.

    It uploads a small file, then tries every way of fetching its bytes:

      A  the @microsoft.graph.downloadUrl from the item's metadata, unauthenticated
      B  the same URL, with the Graph bearer attached
      C  GET /content without following redirects, to see where Graph points
      D  that redirect target, unauthenticated
      E  GET /content following redirects, which is what a browser or the SDK does

    If A and D both fail while the upload succeeded, the content host is refusing
    unauthenticated reads -- a tenant policy, not a bug here. If B or E succeed, there is a
    workable route and the client should use it.

.PARAMETER GraphToken
    A token from Graph Explorer with Files.ReadWrite consented. Prompted for if omitted.

.PARAMETER UseAzureCli
    Take the token from the signed-in Azure CLI instead of prompting.

    Worth running alongside the Graph Explorer result, because the two use different application
    identities. Restrictions of this kind are often scoped to particular client apps, and Graph
    Explorer is a multi-tenant Microsoft app that many organisations single out. If the CLI's
    identity can read content where Graph Explorer cannot, the block is app-specific -- which
    means an application registered inside the tenant would likely work too.

    Sign in to the tenant that owns the OneDrive first:
        az login --tenant <tenant with the OneDrive account>

.EXAMPLE
    .\scripts\diagnose-download.ps1 -UseAzureCli
#>
[CmdletBinding()]
param(
    [string] $GraphToken,
    [switch] $UseAzureCli
)

$ErrorActionPreference = 'Stop'

if ($UseAzureCli) {
    Write-Host 'Taking a Graph token from the Azure CLI...' -ForegroundColor Cyan

    $account = az account show --query '{tenant:tenantId, user:user.name}' -o json 2>$null
    if (-not $account) { throw 'The Azure CLI is not signed in. Run: az login --tenant <tenant>' }

    $accountInfo = $account | ConvertFrom-Json
    Write-Host "  signed in as $($accountInfo.user) in tenant $($accountInfo.tenant)" -ForegroundColor DarkGray

    $tokenJson = az account get-access-token --resource https://graph.microsoft.com -o json 2>$null
    if (-not $tokenJson) { throw 'Could not obtain a Graph token from the Azure CLI.' }

    $GraphToken = ($tokenJson | ConvertFrom-Json).accessToken
    Write-Host '  got a token for the Azure CLI application identity' -ForegroundColor DarkGray
    Write-Host ''
}

if ([string]::IsNullOrWhiteSpace($GraphToken)) {
    $secure = Read-Host -Prompt 'Paste the Graph access token' -AsSecureString
    $GraphToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

if ([string]::IsNullOrWhiteSpace($GraphToken)) { throw 'No token supplied.' }

# Which application the token was issued to is the crux here, so report it. The value is read
# from an unvalidated token purely for display.
try {
    $payload = ($GraphToken -split '\.')[1]
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    $claims = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($payload.Replace('-', '+').Replace('_', '/'))) | ConvertFrom-Json

    $account = $claims.upn
    if ([string]::IsNullOrWhiteSpace($account)) { $account = $claims.preferred_username }

    Write-Host "Token application id : $($claims.appid)" -ForegroundColor DarkGray
    Write-Host "Token account        : $account" -ForegroundColor DarkGray
    Write-Host "Token scopes         : $($claims.scp)" -ForegroundColor DarkGray
}
catch {
    Write-Host 'Could not read the token claims for display.' -ForegroundColor DarkGray
}

$graph = 'https://graph.microsoft.com/v1.0'
$authHeader = @{ Authorization = "Bearer $GraphToken" }
$fileName = "mcp-download-probe-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

function Show-Result {
    param([string] $Label, [scriptblock] $Action)

    Write-Host ("  {0,-52}" -f $Label) -NoNewline

    try {
        $status = & $Action
        if ($status -ge 200 -and $status -lt 300) {
            Write-Host "$status OK" -ForegroundColor Green
        }
        else {
            Write-Host "$status" -ForegroundColor Yellow
        }
        return $status
    }
    catch {
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -eq 0) {
            Write-Host "error: $($_.Exception.Message)" -ForegroundColor Red
        }
        else {
            Write-Host "$status" -ForegroundColor Red
        }
        return $status
    }
}

Write-Host ''
Write-Host 'Diagnosing OneDrive content download, straight against Graph' -ForegroundColor Cyan
Write-Host ''

# --------------------------------------------------------------------- upload a probe file

Write-Host 'Setup' -ForegroundColor Cyan

$uploadUri = "$graph/me/drive/root:/$fileName" + ':/content'
$item = $null

Show-Result 'upload a probe file' {
    $response = Invoke-WebRequest -Uri $uploadUri -Method Put -Headers $authHeader `
        -Body 'probe' -ContentType 'text/plain' -UseBasicParsing
    $script:item = $response.Content | ConvertFrom-Json
    return [int]$response.StatusCode
} | Out-Null

if ($null -eq $item) {
    Write-Host ''
    Write-Host 'The upload failed, so the token itself is the problem. Get a fresh one.' -ForegroundColor Red
    exit 1
}

Write-Host "         item id: $($item.id)" -ForegroundColor DarkGray

# --------------------------------------------------------------------- metadata

Write-Host ''
Write-Host 'Metadata' -ForegroundColor Cyan

$metadata = $null

Show-Result 'fetch item metadata' {
    $response = Invoke-WebRequest -Uri "$graph/me/drive/items/$($item.id)" -Headers $authHeader -UseBasicParsing
    $script:metadata = $response.Content | ConvertFrom-Json
    return [int]$response.StatusCode
} | Out-Null

$downloadUrl = $null
if ($metadata) { $downloadUrl = $metadata.'@microsoft.graph.downloadUrl' }

if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
    Write-Host '         @microsoft.graph.downloadUrl: ABSENT' -ForegroundColor Yellow
}
else {
    $uri = [Uri]$downloadUrl
    # Query keys only. The values carry the signature and are credentials in their own right.
    $keys = ($uri.Query.TrimStart('?') -split '&' | ForEach-Object { ($_ -split '=')[0] }) -join ', '
    Write-Host "         downloadUrl host : $($uri.Host)" -ForegroundColor DarkGray
    Write-Host "         downloadUrl query: $keys" -ForegroundColor DarkGray
}

# --------------------------------------------------------------------- the five routes

Write-Host ''
Write-Host 'Download routes' -ForegroundColor Cyan

$results = @{}

if (-not [string]::IsNullOrWhiteSpace($downloadUrl)) {
    $results['A'] = Show-Result 'A  downloadUrl, no Authorization header' {
        [int](Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing).StatusCode
    }

    $results['B'] = Show-Result 'B  downloadUrl, with the Graph bearer' {
        [int](Invoke-WebRequest -Uri $downloadUrl -Headers $authHeader -UseBasicParsing).StatusCode
    }
}

$contentUri = "$graph/me/drive/items/$($item.id)/content"
$redirectTarget = $null

$results['C'] = Show-Result 'C  GET /content, redirects not followed' {
    $response = Invoke-WebRequest -Uri $contentUri -Headers $authHeader -UseBasicParsing `
        -MaximumRedirection 0 -ErrorAction SilentlyContinue
    if ($response.Headers.Location) { $script:redirectTarget = $response.Headers.Location }
    return [int]$response.StatusCode
}

if ($redirectTarget) {
    Write-Host "         redirects to: $(([Uri]$redirectTarget).Host)" -ForegroundColor DarkGray

    $results['D'] = Show-Result 'D  that redirect target, unauthenticated' {
        [int](Invoke-WebRequest -Uri $redirectTarget -UseBasicParsing).StatusCode
    }
}

$results['E'] = Show-Result 'E  GET /content, redirects followed' {
    [int](Invoke-WebRequest -Uri $contentUri -Headers $authHeader -UseBasicParsing).StatusCode
}

# --------------------------------------------------------------------- cleanup

Write-Host ''
Write-Host 'Cleanup' -ForegroundColor Cyan

Show-Result 'delete the probe file' {
    [int](Invoke-WebRequest -Uri "$graph/me/drive/items/$($item.id)" -Method Delete `
        -Headers $authHeader -UseBasicParsing).StatusCode
} | Out-Null

# --------------------------------------------------------------------- verdict

function Test-Ok { param($code) return ($null -ne $code -and $code -ge 200 -and $code -lt 300) }

Write-Host ''
Write-Host 'Verdict' -ForegroundColor Cyan

$unauthenticatedWorks = (Test-Ok $results['A']) -or (Test-Ok $results['D'])
$authenticatedWorks = (Test-Ok $results['B']) -or (Test-Ok $results['E'])

if ($unauthenticatedWorks) {
    Write-Host '  Unauthenticated content reads work, so the 401 is a bug in this project.' -ForegroundColor Yellow
    Write-Host '  Send this output back -- the fault is in how the server builds that request.'
}
elseif ($authenticatedWorks) {
    Write-Host '  The content host refuses unauthenticated reads, but an authenticated route works.' -ForegroundColor Green
    Write-Host '  This is a tenant policy, not a bug. The server needs to use the authenticated'
    Write-Host '  route, which means accepting a narrower trade-off around where the token goes.'
    if (Test-Ok $results['B']) { Write-Host '  Route B works: the download URL accepts the Graph bearer.' }
    if (Test-Ok $results['E']) { Write-Host '  Route E works: following the /content redirect succeeds.' }
}
else {
    Write-Host '  No route reached the file bytes, even though the upload succeeded.' -ForegroundColor Red
    Write-Host '  That points at a tenant restriction on reading OneDrive content, which needs an'
    Write-Host '  administrator rather than a code change. Send this output back.'
}

Write-Host ''
