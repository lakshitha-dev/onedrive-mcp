<#
.SYNOPSIS
    End-to-end test of the OneDrive MCP server: discovery, registration, the full OAuth sign-in,
    every tool, and the refusal guards.

.DESCRIPTION
    Adapts to how the server is running.

    With authentication on, it drives the complete flow the way a real client does: registers
    itself through Dynamic Client Registration, generates a PKCE pair, opens a browser for the
    Microsoft sign-in and consent, catches the redirect on a local listener, exchanges the code
    for a token, and calls every tool with it. That covers the authorization server and the
    Entra refresh-token bridge -- the parts that cannot be proven any other way.

    With authentication off (a pasted development token), it skips the OAuth phases and exercises
    the tools directly.

    Everything it creates lives in one uniquely named folder and is deleted at the end.

.PARAMETER BaseUrl
    Where the server is listening. Defaults to http://localhost:5170.

.PARAMETER CallbackPort
    Local port used to catch the OAuth redirect. Defaults to 9876.

.PARAMETER SkipOAuth
    Test only the parts that need no token.

.PARAMETER KeepFiles
    Leave the test folder in place for inspection.

.EXAMPLE
    .\scripts\test-all.ps1
#>
[CmdletBinding()]
param(
    [string] $BaseUrl = 'http://localhost:5170',
    [int] $CallbackPort = 9876,
    [switch] $SkipOAuth,
    [switch] $KeepFiles
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell does not load System.Web by default, and the OAuth redirect is parsed with
# HttpUtility. Loading it up front fails here rather than midway through a sign-in.
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Shared with tool.ps1 so both show the same page after the redirect.
. (Join-Path $PSScriptRoot 'CallbackPage.ps1')

# Everything printed here is also written to a file. The browser shows only the last redirect it
# happened to land on, which has twice now looked like a failure when the real story was in this
# window -- so the run records itself rather than relying on what gets copied out of a terminal.
$script:LogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'last-test-run.log'

try {
    Start-Transcript -Path $script:LogPath -Force | Out-Null
    $script:Transcribing = $true
}
catch {
    $script:Transcribing = $false
}

$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0
$script:AccessToken = $null

# Kept for the reuse check that runs last, because provoking it revokes the session.
$script:SupersededRefreshToken = $null
$script:ClientIdForRevocation = $null

# ============================================================================ helpers

function Stop-Run {
    param([int] $Code)

    if ($script:Transcribing) {
        Write-Host ''
        Write-Host "Full output written to: $($script:LogPath)" -ForegroundColor DarkGray
        try { Stop-Transcript | Out-Null } catch { }
    }

    exit $Code
}

function Write-Section {
    param([string] $Name)
    Write-Host ''
    Write-Host $Name -ForegroundColor Cyan
}

function Test-Step {
    param(
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [scriptblock] $Action,
        [switch] $ExpectFailure
    )

    Write-Host ("  {0,-48}" -f $Description) -NoNewline

    try {
        $result = & $Action

        $succeeded = $true
        if ($result -is [pscustomobject] -and $null -ne $result.PSObject.Properties['IsError']) {
            $succeeded = -not $result.IsError
        }
        elseif ($result -is [bool]) {
            $succeeded = $result
        }

        $asExpected = $succeeded
        if ($ExpectFailure) { $asExpected = -not $succeeded }

        if ($asExpected) {
            Write-Host 'PASS' -ForegroundColor Green
            $script:Passed++
            return $result
        }

        Write-Host 'FAIL' -ForegroundColor Red
        if ($result -is [pscustomobject] -and $result.Text) {
            Write-Host "         $($result.Text)" -ForegroundColor DarkGray
        }
        $script:Failed++
        return $result
    }
    catch {
        # A thrown exception means the operation failed, which is the outcome an -ExpectFailure
        # step is asserting. Treating every exception as a failure scored the server's correct
        # refusals -- an HTTP 400 for plain PKCE, say -- as though they were faults.
        if ($ExpectFailure) {
            Write-Host 'PASS' -ForegroundColor Green
            $script:Passed++
            return $null
        }

        Write-Host 'FAIL' -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor DarkGray
        $script:Failed++
        return $null
    }
}

function Skip-Step {
    param([string] $Description, [string] $Reason)
    Write-Host ("  {0,-48}" -f $Description) -NoNewline
    Write-Host "SKIP  $Reason" -ForegroundColor DarkGray
    $script:Skipped++
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [hashtable] $Arguments = @{}
    )

    $body = @{
        jsonrpc = '2.0'
        id      = 1
        method  = 'tools/call'
        params  = @{
            name      = $Name
            arguments = $Arguments
            # The 2026-07-28 revision carries the protocol version and client capabilities in
            # _meta, and repeats the method and tool name as headers.
            '_meta'   = @{
                'io.modelcontextprotocol/protocolVersion'    = '2026-07-28'
                'io.modelcontextprotocol/clientCapabilities' = @{}
            }
        }
    } | ConvertTo-Json -Depth 10 -Compress

    $headers = @{
        'Accept'               = 'application/json, text/event-stream'
        'MCP-Protocol-Version' = '2026-07-28'
        'Mcp-Method'           = 'tools/call'
        'Mcp-Name'             = $Name
    }

    if ($script:AccessToken) { $headers['Authorization'] = "Bearer $($script:AccessToken)" }

    $raw = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body $body `
        -ContentType 'application/json' -Headers $headers -UseBasicParsing

    $line = ($raw.Content -split "`n" | Where-Object { $_ -like 'data:*' } | Select-Object -First 1)
    $payload = $line.Substring(5).Trim() | ConvertFrom-Json

    if ($null -ne $payload.error) {
        return [pscustomobject]@{ IsError = $true; Text = $payload.error.message; Data = $null }
    }

    $isError = $false
    if ($null -ne $payload.result.isError) { $isError = [bool]$payload.result.isError }

    $text = ''
    if ($payload.result.content -and $payload.result.content.Count -gt 0) {
        $text = $payload.result.content[0].text
    }

    return [pscustomobject]@{ IsError = $isError; Text = $text; Data = $payload.result.structuredContent }
}

function Write-Complete {
    <#
        Writes the courtesy page shown in the browser after the redirect.

        Best-effort on purpose. By the time this runs the authorization code has already been
        read, so the page is a nicety -- but a browser that has moved on leaves the connection
        gone, and Response.Close() then throws "an operation was attempted on a nonexistent
        network connection". Under $ErrorActionPreference = 'Stop' that terminates the whole
        script after a successful sign-in, which looks exactly like the sign-in having failed.
    #>
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $Message
    )

    try {
        $outcome = if ($Message -like 'Sign-in failed*') { 'Failure' } else { 'Success' }
        $html = [Text.Encoding]::UTF8.GetBytes((Get-CallbackPageHtml -Outcome $outcome))
        $Context.Response.ContentType = 'text/html; charset=utf-8'
        $Context.Response.OutputStream.Write($html, 0, $html.Length)
        $Context.Response.Close()
    }
    catch {
        Write-Host '  (browser had already disconnected; continuing)' -ForegroundColor DarkGray
    }
}

function New-CodeVerifier {
    $bytes = [byte[]]::new(32)

    # RandomNumberGenerator.Fill is .NET Core only, and Windows PowerShell runs on .NET Framework.
    # RNGCryptoServiceProvider works on both.
    $rng = [Security.Cryptography.RNGCryptoServiceProvider]::new()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }

    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-CodeChallenge {
    param([string] $Verifier)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Verifier))
        return [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    finally { $sha.Dispose() }
}

# ============================================================================ preflight

Write-Host ''
Write-Host "OneDrive MCP end-to-end test against $BaseUrl" -ForegroundColor Cyan

try {
    Invoke-WebRequest -Uri "$BaseUrl/health" -UseBasicParsing -TimeoutSec 5 | Out-Null
}
catch {
    Write-Host ''
    Write-Host 'The server is not responding. Start it with one of:' -ForegroundColor Red
    Write-Host '  .\scripts\run-local.ps1          (development token, no authentication)'
    Write-Host '  .\scripts\run-local-oauth.ps1    (real authentication)'
    Stop-Run 1
}

# Whether authentication is on decides which half of this script applies. An anonymous tool call
# that comes back 401 means the MCP endpoint is protected.
$authRequired = $false
try {
    Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -UseBasicParsing `
        -ContentType 'application/json' -Body '{}' `
        -Headers @{ 'MCP-Protocol-Version' = '2026-07-28'; 'Mcp-Method' = 'tools/list' } | Out-Null
}
catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $authRequired = $true }
}

if ($authRequired) {
    Write-Host 'Mode: authentication ON' -ForegroundColor Green
}
else {
    Write-Host 'Mode: authentication OFF (development token)' -ForegroundColor Yellow
}

# ============================================================================ discovery

Write-Section 'Discovery'

$metadata = $null

Test-Step 'health endpoint is anonymous' {
    [int](Invoke-WebRequest -Uri "$BaseUrl/health" -UseBasicParsing).StatusCode -eq 200
} | Out-Null

if ($authRequired) {
    $metadata = Test-Step 'authorization server metadata' {
        $m = Invoke-RestMethod -Uri "$BaseUrl/.well-known/oauth-authorization-server"
        if (-not $m.token_endpoint) { throw 'no token_endpoint in the document' }
        return $m
    }

    Test-Step 'PKCE S256 is the only method offered' {
        # Plain PKCE gives no protection against someone who can observe the request.
        ($metadata.code_challenge_methods_supported -join ',') -eq 'S256'
    } | Out-Null

    Test-Step 'protected resource metadata' {
        $null -ne (Invoke-RestMethod -Uri "$BaseUrl/.well-known/oauth-protected-resource").authorization_servers
    } | Out-Null

    Test-Step 'signing keys are published' {
        (Invoke-RestMethod -Uri "$BaseUrl/oauth/jwks").keys.Count -ge 1
    } | Out-Null

    Test-Step 'private key material is not published' {
        # "d" is the RSA private exponent; its presence would make this a private key.
        $raw = (Invoke-WebRequest -Uri "$BaseUrl/oauth/jwks" -UseBasicParsing).Content
        -not ($raw -match '"d"')
    } | Out-Null

    Test-Step 'anonymous call is challenged with a pointer' {
        try {
            Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -UseBasicParsing `
                -ContentType 'application/json' -Body '{}' `
                -Headers @{ 'MCP-Protocol-Version' = '2026-07-28'; 'Mcp-Method' = 'tools/list' } | Out-Null
            return $false
        }
        catch {
            $response = $_.Exception.Response
            if (-not $response -or [int]$response.StatusCode -ne 401) { return $false }
            # A bare 401 leaves a client with nowhere to go; the pointer is the useful part.
            return ($response.Headers['WWW-Authenticate'] -match 'resource_metadata')
        }
    } | Out-Null
}
else {
    Skip-Step 'authorization server metadata' 'authentication is off'
}

# ============================================================================ oauth flow

if ($authRequired -and -not $SkipOAuth) {

    Write-Section 'OAuth sign-in'

    $redirectUri = "http://localhost:$CallbackPort/callback/"
    $clientId = $null

    $registration = Test-Step 'register this client (DCR)' {
        $body = @{ client_name = 'onedrive-mcp test-all'; redirect_uris = @($redirectUri) } |
            ConvertTo-Json -Compress
        $created = Invoke-RestMethod -Uri "$BaseUrl/oauth/register" -Method Post `
            -Body $body -ContentType 'application/json'
        if (-not $created.client_id) { throw 'no client_id returned' }
        $script:clientId = $created.client_id
        return $created
    }

    if ($registration) { $clientId = $registration.client_id }

    Test-Step 'plain PKCE is refused' -ExpectFailure {
        $uri = "$BaseUrl/oauth/authorize?response_type=code&client_id=$clientId" +
               "&redirect_uri=$([Uri]::EscapeDataString($redirectUri))" +
               "&code_challenge=abc&code_challenge_method=plain"
        [int](Invoke-WebRequest -Uri $uri -UseBasicParsing -MaximumRedirection 0).StatusCode -lt 400
    } | Out-Null

    Test-Step 'an unregistered redirect URI is refused' -ExpectFailure {
        $uri = "$BaseUrl/oauth/authorize?response_type=code&client_id=$clientId" +
               "&redirect_uri=$([Uri]::EscapeDataString('https://attacker.example/cb'))" +
               "&code_challenge=abc&code_challenge_method=S256"
        [int](Invoke-WebRequest -Uri $uri -UseBasicParsing -MaximumRedirection 0).StatusCode -lt 400
    } | Out-Null

    if ($clientId) {
        $verifier = New-CodeVerifier
        $challenge = Get-CodeChallenge -Verifier $verifier
        $state = [Guid]::NewGuid().ToString('N')

        $authorizeUrl = "$BaseUrl/oauth/authorize?response_type=code&client_id=$clientId" +
                        "&redirect_uri=$([Uri]::EscapeDataString($redirectUri))" +
                        "&code_challenge=$challenge&code_challenge_method=S256&state=$state"

        Write-Host ''
        Write-Host '  A browser window will open for the Microsoft sign-in and consent page.' -ForegroundColor Yellow
        Write-Host '  Complete it and this script will carry on by itself.' -ForegroundColor Yellow
        Write-Host ''

        $listener = [Net.HttpListener]::new()
        $listener.Prefixes.Add("http://localhost:$CallbackPort/callback/")

        $code = $null

        try {
            $listener.Start()
            Start-Process $authorizeUrl | Out-Null

            $context = $null
            $contextTask = $listener.GetContextAsync()

            # Generous, because it covers a human signing in, possibly with MFA.
            if ($contextTask.Wait([TimeSpan]::FromMinutes(3))) { $context = $contextTask.Result }

            if ($context) {
                $query = [Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)
                $code = $query['code']
                $returnedState = $query['state']
                $oauthError = $query['error']

                # Said out loud so a stall after this point is obviously a script problem rather
                # than the sign-in having failed -- the distinction cost a debugging round trip.
                Write-Host '  redirect received, continuing' -ForegroundColor DarkGray
                Write-Host ''

                $message = if ($code) { 'Signed in. You can close this tab and return to the terminal.' }
                           else { "Sign-in failed: $oauthError" }

                Write-Complete -Context $context -Message $message

                Test-Step 'the sign-in returned an authorization code' {
                    -not [string]::IsNullOrWhiteSpace($code)
                } | Out-Null

                Test-Step 'state was echoed back unchanged' {
                    $returnedState -eq $state
                } | Out-Null
            }
            else {
                Write-Host '  Timed out waiting for the sign-in.' -ForegroundColor Red
                $script:Failed++
            }
        }
        finally {
            if ($listener.IsListening) { $listener.Stop() }
            $listener.Close()
        }

        if ($code) {
            Write-Host ''

            $tokenResponse = Test-Step 'exchange the code for a token' {
                $form = @{
                    grant_type    = 'authorization_code'
                    client_id     = $clientId
                    code          = $code
                    redirect_uri  = $redirectUri
                    code_verifier = $verifier
                }
                $token = Invoke-RestMethod -Uri "$BaseUrl/oauth/token" -Method Post -Body $form
                if (-not $token.access_token) { throw 'no access_token returned' }
                $script:AccessToken = $token.access_token
                return $token
            }

            Test-Step 'the same code cannot be redeemed twice' -ExpectFailure {
                # A replayed code would let anyone who saw the redirect mint a second token.
                $form = @{
                    grant_type    = 'authorization_code'
                    client_id     = $clientId
                    code          = $code
                    redirect_uri  = $redirectUri
                    code_verifier = $verifier
                }
                $null -ne (Invoke-RestMethod -Uri "$BaseUrl/oauth/token" -Method Post -Body $form).access_token
            } | Out-Null

            if ($tokenResponse -and $tokenResponse.refresh_token) {
                $script:ClientIdForRevocation = $clientId

                $rotated = Test-Step 'refresh token can be redeemed' {
                    $form = @{
                        grant_type    = 'refresh_token'
                        client_id     = $clientId
                        refresh_token = $tokenResponse.refresh_token
                    }
                    $refreshed = Invoke-RestMethod -Uri "$BaseUrl/oauth/token" -Method Post -Body $form
                    if (-not $refreshed.access_token) { throw 'no access_token returned' }
                    $script:AccessToken = $refreshed.access_token
                    return $refreshed
                }

                Test-Step 'refresh token rotates on use' {
                    $rotated -and $rotated.refresh_token -ne $tokenResponse.refresh_token
                } | Out-Null

                # Held back until the very end. Proving reuse detection means provoking it, which
                # revokes the whole token family and with it the session everything else needs.
                # Running it here previously forced a second sign-in, leaving two near-identical
                # consent pages open -- and clicking the stale one produces a confusing "already
                # used" error that looks like a failure but is the server behaving correctly.
                $script:SupersededRefreshToken = $tokenResponse.refresh_token
            }
        }
    }
}
elseif ($authRequired) {
    Skip-Step 'OAuth sign-in' '-SkipOAuth was given'
}

# ============================================================================ tools

# Without a credential the tool phases cannot run, and every one of them would fail for the same
# uninteresting reason. Report that plainly rather than producing a wall of identical 401s.
if ($authRequired -and -not $script:AccessToken) {
    Write-Host ''
    Write-Host 'No access token, so the tool checks cannot run.' -ForegroundColor Yellow

    if ($SkipOAuth) {
        Write-Host 'That is expected with -SkipOAuth. Run without it to sign in and test the tools.'
    }
    else {
        Write-Host 'The sign-in did not complete, so something above needs looking at first.'
    }

    Write-Host ''
    Write-Host "$($script:Passed) passed, $($script:Failed) failed, $($script:Skipped) skipped." -ForegroundColor Yellow
    if ($script:Failed -eq 0) { Stop-Run 0 } else { Stop-Run 1 }
}

Write-Section 'Authentication status'

$auth = Test-Step 'report how this caller is authenticated' { Invoke-Tool -Name 'onedrive_auth_status' }

if ($auth -and $auth.Data) {
    Write-Host "         token kind: $($auth.Data.tokenKind), direct Graph access: $($auth.Data.canCallGraphDirectly)" -ForegroundColor DarkGray
    if ($auth.Data.subject) {
        Write-Host "         subject: $($auth.Data.subject)" -ForegroundColor DarkGray
    }
}

$probe = Invoke-Tool -Name 'onedrive_get_drive_info'

if ($probe.IsError -and $probe.Text -like 'AUTHENTICATION_REQUIRED*') {
    Write-Host ''
    Write-Host 'The server cannot reach OneDrive for this caller:' -ForegroundColor Red
    Write-Host "  $($probe.Text)" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host "$($script:Passed) passed, $($script:Failed) failed, $($script:Skipped) skipped." -ForegroundColor Yellow
    Stop-Run 1
}

$folder = "McpTestAll-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$filePath = "$folder/hello.txt"
$movedPath = "$folder/renamed.txt"
$awkwardPath = "$folder/Q1 #1 50% (draft) + notes.txt"

Write-Host ''
Write-Host "Working folder: $folder" -ForegroundColor DarkGray

Write-Section 'Browse and read'

$drive = Test-Step 'get drive info' { $probe }

if ($drive -and $drive.Data) {
    $used = [math]::Round($drive.Data.usedBytes / 1GB, 2)
    $total = [math]::Round($drive.Data.totalBytes / 1GB, 2)
    Write-Host "         $($drive.Data.driveType) drive, $used GB of $total GB used" -ForegroundColor DarkGray
}

Test-Step 'list the drive root' { Invoke-Tool -Name 'onedrive_list_files' } | Out-Null

Write-Section 'Write and organise'

Test-Step 'create a folder' {
    Invoke-Tool -Name 'onedrive_create_folder' -Arguments @{ name = $folder }
} | Out-Null

Test-Step 'upload a text file' {
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path = $filePath; content = "Written by test-all at $(Get-Date -Format o)."
    }
} | Out-Null

Test-Step 'upload a binary file (base64)' {
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path = "$folder/bytes.bin"; content = [Convert]::ToBase64String([byte[]](1..64)); encoding = 'base64'
    }
} | Out-Null

Test-Step 'upload a file with awkward characters' {
    # Each of # % ? + breaks Graph addressing unless every path segment is percent-encoded.
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path = $awkwardPath; content = 'Round-trips only if each path segment is escaped.'
    }
} | Out-Null

Test-Step 'list the new folder' {
    Invoke-Tool -Name 'onedrive_list_files' -Arguments @{ folderPath = $folder }
} | Out-Null

$read = Test-Step 'read the text file back' {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = $filePath }
}

if ($read -and $read.Data -and $read.Data.content) {
    Write-Host "         content: $($read.Data.content)" -ForegroundColor DarkGray
}

Test-Step 'read the awkward filename back' {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = $awkwardPath }
} | Out-Null

Test-Step 'rename a file' {
    Invoke-Tool -Name 'onedrive_move_item' -Arguments @{ path = $filePath; newName = 'renamed.txt' }
} | Out-Null

Test-Step 'get item details' {
    Invoke-Tool -Name 'onedrive_get_item' -Arguments @{ path = $movedPath }
} | Out-Null

Write-Section 'Search'

Test-Step 'search the drive' {
    Invoke-Tool -Name 'onedrive_search' -Arguments @{ query = 'McpTestAll' }
} | Out-Null

Test-Step 'search with an apostrophe (OData escaping)' {
    Invoke-Tool -Name 'onedrive_search' -Arguments @{ query = "O'Brien" }
} | Out-Null

Test-Step 'list recent files' { Invoke-Tool -Name 'onedrive_list_recent' } | Out-Null

Write-Section 'Sharing'

$link = Test-Step 'create an organisation sharing link' {
    Invoke-Tool -Name 'onedrive_create_share_link' -Arguments @{ path = $movedPath; linkType = 'view' }
}

if ($link -and $link.Data -and $link.Data.url) {
    Write-Host "         $($link.Data.url)" -ForegroundColor DarkGray
}

Test-Step 'list permissions' {
    Invoke-Tool -Name 'onedrive_list_permissions' -Arguments @{ path = $movedPath }
} | Out-Null

if ($link -and $link.Data -and $link.Data.permissionId) {
    Test-Step 'revoke the sharing link' {
        Invoke-Tool -Name 'onedrive_delete_permission' -Arguments @{
            path = $movedPath; permissionId = $link.Data.permissionId
        }
    } | Out-Null
}

Write-Section 'Guards (these should refuse)'

Test-Step 'path traversal' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = '../../secrets.txt' }
} | Out-Null

Test-Step 'encoded path traversal' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = '%2E%2E%2Fsecrets.txt' }
} | Out-Null

Test-Step 'anonymous sharing link' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_create_share_link' -Arguments @{ path = $movedPath; scope = 'anonymous' }
} | Out-Null

Test-Step 'download URL request' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_get_download_url' -Arguments @{ path = $movedPath }
} | Out-Null

Test-Step 'delete with no target' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_delete_item'
} | Out-Null

Test-Step 'both path and itemId together' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_get_item' -Arguments @{ path = 'a.txt'; itemId = '01ABC' }
} | Out-Null

Test-Step 'invalid base64 content' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path = "$folder/bad.bin"; content = '!!! not base64 !!!'; encoding = 'base64'
    }
} | Out-Null

# ============================================================================ cleanup

Write-Section 'Cleanup'

if ($KeepFiles) {
    Skip-Step 'delete the test folder' '-KeepFiles was given'
}
else {
    Test-Step 'delete the test folder' {
        Invoke-Tool -Name 'onedrive_delete_item' -Arguments @{ path = $folder }
    } | Out-Null
}

# ============================================================================ token revocation

# Last, because it deliberately revokes the token family this run has been using.
if ($script:SupersededRefreshToken -and $script:ClientIdForRevocation) {

    Write-Section 'Refresh token reuse (revokes this session)'

    Test-Step 'a superseded refresh token is refused' -ExpectFailure {
        $form = @{
            grant_type    = 'refresh_token'
            client_id     = $script:ClientIdForRevocation
            refresh_token = $script:SupersededRefreshToken
        }
        $null -ne (Invoke-RestMethod -Uri "$BaseUrl/oauth/token" -Method Post -Body $form).access_token
    } | Out-Null

    Test-Step 'the whole token family is now revoked' -ExpectFailure {
        # Reuse means one of two holders is an attacker with no way to tell which, so both are
        # cut off and the user signs in again. Losing the good session is the intended outcome.
        Invoke-Tool -Name 'onedrive_get_drive_info'
    } | Out-Null
}

# ============================================================================ result

Write-Host ''

if ($script:Failed -eq 0) {
    Write-Host "All $($script:Passed) checks passed. ($($script:Skipped) skipped)" -ForegroundColor Green
}
else {
    Write-Host "$($script:Passed) passed, $($script:Failed) failed, $($script:Skipped) skipped." -ForegroundColor Red
}

if ($script:Failed -eq 0) { Stop-Run 0 } else { Stop-Run 1 }
