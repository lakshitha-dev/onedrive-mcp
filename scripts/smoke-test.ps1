<#
.SYNOPSIS
    Exercises every OneDrive MCP tool group against a running server.

.DESCRIPTION
    Walks a realistic sequence -- create a folder, upload, list, read back, search, share, revoke,
    delete -- and reports each step. Everything is created under a uniquely named folder and
    removed at the end, so a run leaves the drive as it found it.

    Also checks the two guards that should refuse: a path traversal, and an anonymous sharing
    link. Those are expected failures and are reported as passes when they are refused.

.PARAMETER BaseUrl
    Where the server is listening. Defaults to http://localhost:5170.

.PARAMETER KeepFiles
    Leave the test folder in place so it can be inspected in the OneDrive web UI.

.EXAMPLE
    .\scripts\smoke-test.ps1
#>
[CmdletBinding()]
param(
    [string] $BaseUrl = 'http://localhost:5170',
    [switch] $KeepFiles
)

$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

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
            # The 2026-07-28 protocol revision carries the version and client capabilities in
            # _meta, and repeats the method and tool name as headers.
            '_meta'   = @{
                'io.modelcontextprotocol/protocolVersion'   = '2026-07-28'
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

    $raw = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body $body `
        -ContentType 'application/json' -Headers $headers -UseBasicParsing

    # Responses come back as a one-event SSE stream.
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

    return [pscustomobject]@{
        IsError = $isError
        Text    = $text
        Data    = $payload.result.structuredContent
    }
}

function Test-Step {
    param(
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [scriptblock] $Action,
        [switch] $ExpectFailure
    )

    Write-Host ("  {0,-46}" -f $Description) -NoNewline

    try {
        $result = & $Action

        $succeeded = -not $result.IsError
        $asExpected = if ($ExpectFailure) { -not $succeeded } else { $succeeded }

        if ($asExpected) {
            Write-Host 'PASS' -ForegroundColor Green
            $script:Passed++
            return $result
        }

        Write-Host 'FAIL' -ForegroundColor Red
        if ($result.Text) { Write-Host "         $($result.Text)" -ForegroundColor DarkGray }
        $script:Failed++
        return $result
    }
    catch {
        Write-Host 'FAIL' -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor DarkGray
        $script:Failed++
        return $null
    }
}

# --------------------------------------------------------------------------- preflight

Write-Host ''
Write-Host "OneDrive MCP smoke test against $BaseUrl" -ForegroundColor Cyan
Write-Host ''

try {
    Invoke-WebRequest -Uri "$BaseUrl/health" -UseBasicParsing -TimeoutSec 5 | Out-Null
}
catch {
    Write-Host 'The server is not responding. Start it first:' -ForegroundColor Red
    Write-Host '  .\scripts\run-local.ps1'
    exit 1
}

# Probe with a real Graph call rather than onedrive_auth_status. That tool reports the *caller's*
# credential, and this script deliberately sends none -- in dev-token mode the caller is anonymous
# while the server still reaches Graph perfectly well, so asking it here answers the wrong
# question and reports a failure that is not one.
$probe = Invoke-Tool -Name 'onedrive_get_drive_info'

if ($probe.IsError -and $probe.Text -like 'AUTHENTICATION_REQUIRED*') {
    Write-Host 'The server cannot reach OneDrive: no Graph credential is configured.' -ForegroundColor Red
    Write-Host 'Start it with a token:  .\scripts\run-local.ps1'
    Write-Host ''
    Write-Host "  $($probe.Text)" -ForegroundColor DarkGray
    exit 1
}

if ($probe.IsError) {
    Write-Host 'The server rejected a basic OneDrive call, so the rest would not be meaningful:' -ForegroundColor Red
    Write-Host "  $($probe.Text)" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'If this mentions an expired token, get a fresh one -- Graph Explorer tokens last about an hour.'
    exit 1
}

$folder = "McpSmokeTest-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$filePath = "$folder/hello.txt"
$movedPath = "$folder/renamed.txt"

Write-Host "Working folder: $folder"
Write-Host ''

# --------------------------------------------------------------------------- browse and read

Write-Host 'Browse and read' -ForegroundColor Cyan

# Reuses the preflight probe rather than calling Graph a second time for the same answer.
$drive = Test-Step 'get drive info' { $probe }

if ($drive -and $drive.Data) {
    $used = [math]::Round($drive.Data.usedBytes / 1GB, 2)
    $total = [math]::Round($drive.Data.totalBytes / 1GB, 2)
    Write-Host "         $($drive.Data.driveType) drive, $used GB of $total GB used" -ForegroundColor DarkGray
}

Test-Step 'list drive root' { Invoke-Tool -Name 'onedrive_list_files' } | Out-Null

# --------------------------------------------------------------------------- write

Write-Host ''
Write-Host 'Write and organise' -ForegroundColor Cyan

Test-Step 'create folder' {
    Invoke-Tool -Name 'onedrive_create_folder' -Arguments @{ name = $folder }
} | Out-Null

Test-Step 'upload a text file' {
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path    = $filePath
        content = "Written by the OneDrive MCP smoke test at $(Get-Date -Format o)."
    }
} | Out-Null

Test-Step 'upload a binary file (base64)' {
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path     = "$folder/bytes.bin"
        content  = [Convert]::ToBase64String([byte[]](1..64))
        encoding = 'base64'
    }
} | Out-Null

Test-Step 'list the new folder' {
    Invoke-Tool -Name 'onedrive_list_files' -Arguments @{ folderPath = $folder }
} | Out-Null

$read = Test-Step 'read the file back' {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = $filePath }
}

if ($read -and $read.Data) {
    Write-Host "         content: $($read.Data.content)" -ForegroundColor DarkGray
}

Test-Step 'rename it' {
    Invoke-Tool -Name 'onedrive_move_item' -Arguments @{ path = $filePath; newName = 'renamed.txt' }
} | Out-Null

# A filename full of characters that break Graph addressing unless each path segment is escaped.
Test-Step 'upload a file with awkward characters' {
    Invoke-Tool -Name 'onedrive_upload_file' -Arguments @{
        path    = "$folder/Q1 #1 50% (draft) + notes.txt"
        content = 'Round-trips only if every path segment is percent-encoded.'
    }
} | Out-Null

Test-Step 'read that file back' {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{
        path = "$folder/Q1 #1 50% (draft) + notes.txt"
    }
} | Out-Null

# --------------------------------------------------------------------------- search

Write-Host ''
Write-Host 'Search' -ForegroundColor Cyan

Test-Step 'search the drive' {
    Invoke-Tool -Name 'onedrive_search' -Arguments @{ query = 'McpSmokeTest' }
} | Out-Null

Test-Step "search with an apostrophe (OData escaping)" {
    Invoke-Tool -Name 'onedrive_search' -Arguments @{ query = "O'Brien" }
} | Out-Null

Test-Step 'list recent files' { Invoke-Tool -Name 'onedrive_list_recent' } | Out-Null

# --------------------------------------------------------------------------- sharing

Write-Host ''
Write-Host 'Sharing' -ForegroundColor Cyan

$link = Test-Step 'create an organisation sharing link' {
    Invoke-Tool -Name 'onedrive_create_share_link' -Arguments @{ path = $movedPath; linkType = 'view' }
}

if ($link -and $link.Data) {
    Write-Host "         $($link.Data.url)" -ForegroundColor DarkGray
}

Test-Step 'list permissions' {
    Invoke-Tool -Name 'onedrive_list_permissions' -Arguments @{ path = $movedPath }
} | Out-Null

if ($link -and $link.Data -and $link.Data.permissionId) {
    Test-Step 'revoke the link' {
        Invoke-Tool -Name 'onedrive_delete_permission' -Arguments @{
            path         = $movedPath
            permissionId = $link.Data.permissionId
        }
    } | Out-Null
}

# --------------------------------------------------------------------------- guards

Write-Host ''
Write-Host 'Guards (these should refuse)' -ForegroundColor Cyan

Test-Step 'reject a path traversal' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = '../../secrets.txt' }
} | Out-Null

Test-Step 'reject an encoded traversal' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_read_text_file' -Arguments @{ path = '%2E%2E%2Fsecrets.txt' }
} | Out-Null

Test-Step 'reject an anonymous sharing link' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_create_share_link' -Arguments @{ path = $movedPath; scope = 'anonymous' }
} | Out-Null

Test-Step 'reject a download URL request' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_get_download_url' -Arguments @{ path = $movedPath }
} | Out-Null

Test-Step 'reject a delete with no target' -ExpectFailure {
    Invoke-Tool -Name 'onedrive_delete_item'
} | Out-Null

# --------------------------------------------------------------------------- cleanup

Write-Host ''

if ($KeepFiles) {
    Write-Host "Leaving $folder in place for inspection." -ForegroundColor Yellow
}
else {
    Write-Host 'Cleanup' -ForegroundColor Cyan

    Test-Step 'delete the test folder' {
        Invoke-Tool -Name 'onedrive_delete_item' -Arguments @{ path = $folder }
    } | Out-Null
}

# --------------------------------------------------------------------------- result

Write-Host ''

if ($script:Failed -eq 0) {
    Write-Host "All $($script:Passed) checks passed." -ForegroundColor Green
    exit 0
}

Write-Host "$($script:Passed) passed, $($script:Failed) failed." -ForegroundColor Red
exit 1
