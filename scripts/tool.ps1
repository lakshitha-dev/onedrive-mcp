<#
.SYNOPSIS
    Calls one OneDrive MCP tool at a time, for exploring the server by hand.

.DESCRIPTION
    Signs in once and caches the access token, so a session of one-at-a-time calls needs a single
    browser round trip rather than one per call. The cached token is reused until it expires.

    With authentication off (run-local.ps1 with a development token), no sign-in happens at all.

.PARAMETER Name
    The tool to call, for example onedrive_list_files. The onedrive_ prefix may be omitted.

.PARAMETER Arguments
    Tool arguments as a hashtable, for example @{ name = 'Reports'; parentPath = 'Documents' }.

.PARAMETER List
    List the available tools instead of calling one.

.PARAMETER Describe
    Show a tool's parameters and description instead of calling it.

.PARAMETER Interactive
    Pick tools from a menu and be prompted for their arguments.

.PARAMETER Raw
    Print the raw JSON result rather than a formatted view.

.PARAMETER SignOut
    Discard the cached token, so the next call signs in again.

.EXAMPLE
    .\scripts\tool.ps1 -List

.EXAMPLE
    .\scripts\tool.ps1 -Describe create_folder

.EXAMPLE
    .\scripts\tool.ps1 create_folder -Arguments @{ name = 'Test Folder' }

.EXAMPLE
    .\scripts\tool.ps1 list_files -Arguments @{ folderPath = 'Test Folder' }

.EXAMPLE
    .\scripts\tool.ps1 -Interactive
#>
[CmdletBinding(DefaultParameterSetName = 'Call')]
param(
    [Parameter(ParameterSetName = 'Call', Position = 0)]
    [string] $Name,

    [Parameter(ParameterSetName = 'Call')]
    [hashtable] $Arguments = @{},

    [Parameter(ParameterSetName = 'List')]
    [switch] $List,

    [Parameter(ParameterSetName = 'Describe')]
    [string] $Describe,

    [Parameter(ParameterSetName = 'Interactive')]
    [switch] $Interactive,

    [switch] $Raw,
    [switch] $SignOut,

    [string] $BaseUrl = 'http://localhost:5170',
    [int] $CallbackPort = 9876
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Shared with test-all.ps1 so both show the same page after the redirect.
. (Join-Path $PSScriptRoot 'CallbackPage.ps1')

$script:TokenCachePath = Join-Path (Split-Path -Parent $PSScriptRoot) '.mcp-session.json'
$script:AccessToken = $null

# ============================================================================ session

function Clear-Session {
    if (Test-Path $script:TokenCachePath) {
        Remove-Item $script:TokenCachePath -Force
        Write-Host 'Signed out.' -ForegroundColor Green
    }
    else {
        Write-Host 'No cached session.' -ForegroundColor DarkGray
    }
}

function Get-TokenExpiry {
    param([string] $Token)

    try {
        $payload = ($Token -split '\.')[1]
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        $json = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($payload.Replace('-', '+').Replace('_', '/')))
        $exp = ($json | ConvertFrom-Json).exp

        if ($exp) { return [DateTimeOffset]::FromUnixTimeSeconds([long]$exp) }
    }
    catch { }

    return [DateTimeOffset]::MinValue
}

function Get-CachedToken {
    if (-not (Test-Path $script:TokenCachePath)) { return $null }

    try {
        $cached = (Get-Content $script:TokenCachePath -Raw | ConvertFrom-Json).accessToken
        if (-not $cached) { return $null }

        # A minute of headroom, so a call cannot start with a token that lapses mid-flight.
        if ((Get-TokenExpiry -Token $cached) -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) {
            return $cached
        }

        Write-Host 'Cached session has expired; signing in again.' -ForegroundColor DarkGray
    }
    catch { }

    return $null
}

function Save-Token {
    param([string] $Token)

    @{ accessToken = $Token } | ConvertTo-Json | Set-Content -Path $script:TokenCachePath -Encoding UTF8
}

function Test-AuthRequired {
    try {
        Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -UseBasicParsing `
            -ContentType 'application/json' -Body '{}' `
            -Headers @{ 'MCP-Protocol-Version' = '2026-07-28'; 'Mcp-Method' = 'tools/list' } | Out-Null
        return $false
    }
    catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { return $true }
        return $false
    }
}

function Invoke-SignIn {
    $redirectUri = "http://localhost:$CallbackPort/callback/"

    $registration = Invoke-RestMethod -Uri "$BaseUrl/oauth/register" -Method Post `
        -ContentType 'application/json' `
        -Body (@{ client_name = 'onedrive-mcp tool.ps1'; redirect_uris = @($redirectUri) } |
            ConvertTo-Json -Compress)

    $bytes = [byte[]]::new(32)
    $rng = [Security.Cryptography.RNGCryptoServiceProvider]::new()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $verifier = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)) } finally { $sha.Dispose() }
    $challenge = [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $authorizeUrl = "$BaseUrl/oauth/authorize?response_type=code" +
                    "&client_id=$($registration.client_id)" +
                    "&redirect_uri=$([Uri]::EscapeDataString($redirectUri))" +
                    "&code_challenge=$challenge&code_challenge_method=S256"

    Write-Host ''
    Write-Host 'Signing in. A browser window will open; complete it and come back.' -ForegroundColor Yellow

    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add("http://localhost:$CallbackPort/callback/")
    $code = $null

    try {
        $listener.Start()
        Start-Process $authorizeUrl | Out-Null

        $task = $listener.GetContextAsync()

        if ($task.Wait([TimeSpan]::FromMinutes(3))) {
            $context = $task.Result
            $code = [Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)['code']

            # Best-effort: the code is already in hand, and a browser that has moved on makes
            # Close() throw, which would otherwise abort the sign-in that just succeeded.
            try {
                $outcome = if ($code) { 'Success' } else { 'Failure' }
                $html = [Text.Encoding]::UTF8.GetBytes((Get-CallbackPageHtml -Outcome $outcome))
                $context.Response.ContentType = 'text/html; charset=utf-8'
                $context.Response.OutputStream.Write($html, 0, $html.Length)
                $context.Response.Close()
            }
            catch { }
        }
    }
    finally {
        if ($listener.IsListening) { $listener.Stop() }
        $listener.Close()
    }

    if (-not $code) { throw 'Sign-in did not complete.' }

    $token = Invoke-RestMethod -Uri "$BaseUrl/oauth/token" -Method Post -Body @{
        grant_type    = 'authorization_code'
        client_id     = $registration.client_id
        code          = $code
        redirect_uri  = $redirectUri
        code_verifier = $verifier
    }

    Save-Token -Token $token.access_token
    Write-Host 'Signed in.' -ForegroundColor Green
    Write-Host ''

    return $token.access_token
}

function Initialize-Session {
    if (-not (Test-AuthRequired)) { return }

    $script:AccessToken = Get-CachedToken

    if (-not $script:AccessToken) {
        $script:AccessToken = Invoke-SignIn
    }
}

# ============================================================================ mcp

function Invoke-Mcp {
    param(
        [Parameter(Mandatory)] [string] $Method,
        [string] $McpName,
        [hashtable] $Parameters = @{}
    )

    $Parameters['_meta'] = @{
        'io.modelcontextprotocol/protocolVersion'    = '2026-07-28'
        'io.modelcontextprotocol/clientCapabilities' = @{}
    }

    $body = @{ jsonrpc = '2.0'; id = 1; method = $Method; params = $Parameters } |
        ConvertTo-Json -Depth 12 -Compress

    $headers = @{
        'Accept'               = 'application/json, text/event-stream'
        'MCP-Protocol-Version' = '2026-07-28'
        'Mcp-Method'           = $Method
    }

    if ($McpName) { $headers['Mcp-Name'] = $McpName }
    if ($script:AccessToken) { $headers['Authorization'] = "Bearer $($script:AccessToken)" }

    $raw = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body $body `
        -ContentType 'application/json' -Headers $headers -UseBasicParsing

    $line = ($raw.Content -split "`n" | Where-Object { $_ -like 'data:*' } | Select-Object -First 1)
    return $line.Substring(5).Trim() | ConvertFrom-Json
}

function Get-Tools {
    return (Invoke-Mcp -Method 'tools/list').result.tools
}

function Resolve-ToolName {
    param([string] $Requested, $Tools)

    $match = $Tools | Where-Object { $_.name -eq $Requested }
    if ($match) { return $match.name }

    # Typing the onedrive_ prefix every time gets tedious.
    $match = $Tools | Where-Object { $_.name -eq "onedrive_$Requested" }
    if ($match) { return $match.name }

    $partial = @($Tools | Where-Object { $_.name -like "*$Requested*" })

    if ($partial.Count -eq 1) { return $partial[0].name }

    if ($partial.Count -gt 1) {
        Write-Host "'$Requested' matches more than one tool:" -ForegroundColor Yellow
        $partial | ForEach-Object { Write-Host "  $($_.name)" }
        throw 'Be more specific.'
    }

    throw "No tool matches '$Requested'. Use -List to see them."
}

function Show-Tools {
    param($Tools)

    Write-Host ''
    Write-Host "$($Tools.Count) tools" -ForegroundColor Cyan
    Write-Host ''

    foreach ($tool in ($Tools | Sort-Object name)) {
        $hints = @()
        if ($tool.annotations.readOnlyHint) { $hints += 'read-only' }
        if ($tool.annotations.destructiveHint) { $hints += 'DESTRUCTIVE' }

        $label = if ($hints.Count -gt 0) { " [$($hints -join ', ')]" } else { '' }
        $colour = if ($tool.annotations.destructiveHint) { 'Yellow' } else { 'Gray' }

        Write-Host ("  {0}{1}" -f $tool.name, $label) -ForegroundColor $colour
    }

    Write-Host ''
    Write-Host 'Details:  .\scripts\tool.ps1 -Describe <name>' -ForegroundColor DarkGray
    Write-Host 'Call:     .\scripts\tool.ps1 <name> -Arguments @{ key = ''value'' }' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Tool {
    param($Tool)

    Write-Host ''
    Write-Host $Tool.name -ForegroundColor Cyan

    if ($Tool.annotations.destructiveHint) {
        Write-Host '  DESTRUCTIVE - changes or exposes data' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host "  $($Tool.description)"
    Write-Host ''

    $required = @()
    if ($Tool.inputSchema.required) { $required = @($Tool.inputSchema.required) }

    $properties = $Tool.inputSchema.properties

    if (-not $properties -or -not $properties.PSObject.Properties.Name) {
        Write-Host '  No parameters.' -ForegroundColor DarkGray
        Write-Host ''
        return
    }

    Write-Host '  Parameters:' -ForegroundColor Cyan

    foreach ($property in $properties.PSObject.Properties) {
        $mark = if ($required -contains $property.Name) { '*' } else { ' ' }
        Write-Host ("    {0}{1}" -f $mark, $property.Name) -ForegroundColor Gray

        if ($property.Value.description) {
            Write-Host "       $($property.Value.description)" -ForegroundColor DarkGray
        }
    }

    Write-Host ''
    Write-Host '  * = required' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Result {
    param($Response, [string] $ToolName)

    $result = $Response.result

    if ($null -ne $Response.error) {
        Write-Host "ERROR: $($Response.error.message)" -ForegroundColor Red
        return
    }

    $isError = $false
    if ($null -ne $result.isError) { $isError = [bool]$result.isError }

    $text = ''
    if ($result.content -and $result.content.Count -gt 0) { $text = $result.content[0].text }

    if ($isError) {
        Write-Host "FAILED  $ToolName" -ForegroundColor Red
        Write-Host "  $text" -ForegroundColor DarkGray
        return
    }

    Write-Host "OK      $ToolName" -ForegroundColor Green

    if ($Raw) {
        Write-Host ($result | ConvertTo-Json -Depth 12)
        return
    }

    if ($result.structuredContent) {
        Write-Host ($result.structuredContent | ConvertTo-Json -Depth 8)
    }
    elseif ($text) {
        Write-Host $text
    }
}

function Invoke-Interactive {
    param($Tools)

    while ($true) {
        Write-Host ''
        Write-Host 'Pick a tool (number, name, or q to quit)' -ForegroundColor Cyan

        $ordered = @($Tools | Sort-Object name)

        for ($i = 0; $i -lt $ordered.Count; $i++) {
            $marker = if ($ordered[$i].annotations.destructiveHint) { '!' } else { ' ' }
            Write-Host ("  {0,2}{1} {2}" -f ($i + 1), $marker, $ordered[$i].name)
        }

        $choice = Read-Host 'Tool'

        if ($choice -in @('q', 'quit', 'exit')) { break }
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        $tool = $null

        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $ordered.Count) {
            $tool = $ordered[[int]$choice - 1]
        }
        else {
            try { $tool = $ordered | Where-Object { $_.name -eq (Resolve-ToolName -Requested $choice -Tools $Tools) } }
            catch { Write-Host $_.Exception.Message -ForegroundColor Red; continue }
        }

        Show-Tool -Tool $tool

        $callArguments = @{}
        $properties = $tool.inputSchema.properties
        $required = @()
        if ($tool.inputSchema.required) { $required = @($tool.inputSchema.required) }

        if ($properties -and $properties.PSObject.Properties.Name) {
            $names = @($properties.PSObject.Properties.Name)

            # A flat JSON schema cannot say "exactly one of these", so every addressing parameter
            # shows as optional and skipping them all produces a rejection that reads as a bug.
            # The tool descriptions say it; the prompts should too.
            $needsTarget = ($names -contains 'path') -and ($names -contains 'itemId')

            # Ask for one or the other rather than both. Prompting for each in turn invites
            # filling them all in, which the server then refuses -- a mistake the interface
            # created rather than the user.
            if ($needsTarget) {
                Write-Host '  Identify the item by path OR by itemId.' -ForegroundColor Yellow
                Write-Host ''

                $pathValue = Read-Host 'path (Enter to use itemId instead)'

                if (-not [string]::IsNullOrWhiteSpace($pathValue)) {
                    $callArguments['path'] = $pathValue
                }
                else {
                    $idValue = Read-Host 'itemId'

                    if (-not [string]::IsNullOrWhiteSpace($idValue)) {
                        $callArguments['itemId'] = $idValue

                        if ($names -contains 'driveId') {
                            $driveValue = Read-Host 'driveId (only for another user''s drive, Enter to skip)'

                            if (-not [string]::IsNullOrWhiteSpace($driveValue)) {
                                $callArguments['driveId'] = $driveValue
                            }
                        }
                    }
                }
            }

            foreach ($property in $properties.PSObject.Properties) {
                # Already handled above, and asking again would let both be set.
                if ($needsTarget -and $property.Name -in @('path', 'itemId', 'driveId')) { continue }

                $isRequired = $required -contains $property.Name
                $prompt = if ($isRequired) { "$($property.Name) (required)" } else { "$($property.Name) (optional, Enter to skip)" }
                $value = Read-Host $prompt

                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    # Numbers arrive as strings from Read-Host; send them as numbers so the
                    # schema matches.
                    if ($property.Value.type -eq 'integer' -and $value -match '^\d+$') {
                        $callArguments[$property.Name] = [int]$value
                    }
                    else {
                        $callArguments[$property.Name] = $value
                    }
                }
            }
        }

        # Caught before the call rather than after, so the answer comes back as guidance instead
        # of a rejection from the server.
        if ($needsTarget -and -not ($callArguments.ContainsKey('path') -or $callArguments.ContainsKey('itemId'))) {
            Write-Host ''
            Write-Host '  No path or itemId given, so there is nothing to act on.' -ForegroundColor Yellow
            Write-Host '  (Skipping the call; the server would refuse it.)' -ForegroundColor DarkGray
            continue
        }

        if ($tool.annotations.destructiveHint) {
            $confirm = Read-Host "This changes or exposes data. Continue? (y/n)"
            if ($confirm -ne 'y') { continue }
        }

        Write-Host ''

        try {
            $response = Invoke-Mcp -Method 'tools/call' -McpName $tool.name `
                -Parameters @{ name = $tool.name; arguments = $callArguments }
            Show-Result -Response $response -ToolName $tool.name
        }
        catch {
            Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ============================================================================ main

if ($SignOut) { Clear-Session; return }

try {
    Invoke-WebRequest -Uri "$BaseUrl/health" -UseBasicParsing -TimeoutSec 5 | Out-Null
}
catch {
    Write-Host "No server at $BaseUrl. Start it with:" -ForegroundColor Red
    Write-Host '  .\scripts\run-local.ps1          (development token, no sign-in)'
    Write-Host '  .\scripts\run-local-oauth.ps1    (real authentication)'
    return
}

Initialize-Session

$tools = Get-Tools

if ($List) { Show-Tools -Tools $tools; return }

if ($Describe) {
    $resolved = Resolve-ToolName -Requested $Describe -Tools $tools
    Show-Tool -Tool ($tools | Where-Object { $_.name -eq $resolved })
    return
}

if ($Interactive) { Invoke-Interactive -Tools $tools; return }

if ([string]::IsNullOrWhiteSpace($Name)) {
    Show-Tools -Tools $tools
    return
}

$resolvedName = Resolve-ToolName -Requested $Name -Tools $tools

Write-Host ''
$response = Invoke-Mcp -Method 'tools/call' -McpName $resolvedName `
    -Parameters @{ name = $resolvedName; arguments = $Arguments }

Show-Result -Response $response -ToolName $resolvedName
Write-Host ''
