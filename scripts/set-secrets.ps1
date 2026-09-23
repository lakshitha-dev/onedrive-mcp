<#
.SYNOPSIS
    Stores the Entra tenant, client id and client secret in .NET user secrets, so they do not
    have to be typed on every run.

.DESCRIPTION
    User secrets live in your Windows profile, not in the repository:

        %APPDATA%\Microsoft\UserSecrets\onedrive-mcp-server\secrets.json

    That is the point -- there is no path by which they reach source control, and a secret that
    reaches source control stays in the history after the commit is amended away. ASP.NET Core
    loads them automatically in Development, so once stored, run-local-oauth.ps1 needs no
    arguments.

    Environment variables still take precedence over user secrets, so a one-off override on the
    command line continues to work.

.PARAMETER TenantId
    The Entra tenant that owns the OneDrive account.

.PARAMETER ClientId
    Application (client) id of the registration.

.PARAMETER ClientSecret
    A client secret for that registration. Prompted for if omitted.

.PARAMETER Clear
    Remove the stored values instead of setting them.

.EXAMPLE
    .\scripts\set-secrets.ps1 -TenantId <guid> -ClientId <guid>
#>
[CmdletBinding()]
param(
    [string] $TenantId,
    [string] $ClientId,
    [string] $ClientSecret,
    [switch] $Clear
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repoRoot 'src/OneDriveMcp.Server'

if ($Clear) {
    Write-Host 'Removing stored secrets...' -ForegroundColor Cyan
    foreach ($key in @('OneDrive:OboTenantId', 'OneDrive:OboClientId', 'OneDrive:OboClientSecret')) {
        dotnet user-secrets remove $key --project $project 2>$null | Out-Null
    }
    Write-Host 'Done.' -ForegroundColor Green
    exit 0
}

# If the secret was parked in the temporary file while it was moved out of .env.example, offer
# to take it from there rather than making it be typed again.
$backup = Join-Path $repoRoot '.tmp-secret-backup.txt'

if ([string]::IsNullOrWhiteSpace($ClientSecret) -and (Test-Path $backup)) {
    $line = Get-Content $backup | Where-Object { $_ -match '^\s*client_secret\s*=' } | Select-Object -First 1

    if ($line) {
        $candidate = ($line -split '=', 2)[1].Trim()

        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            Write-Host "Found a client secret in $(Split-Path -Leaf $backup)." -ForegroundColor Cyan
            $answer = Read-Host 'Use it? (y/n)'

            if ($answer -eq 'y') { $ClientSecret = $candidate }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($TenantId)) {
    $TenantId = Read-Host 'Entra tenant id'
}

if ([string]::IsNullOrWhiteSpace($ClientId)) {
    $ClientId = Read-Host 'Application (client) id'
}

if ([string]::IsNullOrWhiteSpace($ClientSecret)) {
    $secure = Read-Host -Prompt 'Client secret' -AsSecureString
    $ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

foreach ($pair in @(
    @{ Name = 'TenantId'; Value = $TenantId },
    @{ Name = 'ClientId'; Value = $ClientId },
    @{ Name = 'ClientSecret'; Value = $ClientSecret })) {

    if ([string]::IsNullOrWhiteSpace($pair.Value)) {
        throw "$($pair.Name) was not supplied."
    }
}

Write-Host ''
Write-Host 'Storing in user secrets...' -ForegroundColor Cyan

dotnet user-secrets init --project $project | Out-Null
dotnet user-secrets set 'OneDrive:OboTenantId' $TenantId --project $project | Out-Null
dotnet user-secrets set 'OneDrive:OboClientId' $ClientId --project $project | Out-Null
dotnet user-secrets set 'OneDrive:OboClientSecret' $ClientSecret --project $project | Out-Null

# Read back to confirm they landed, with the secret masked -- a stored secret is still a secret,
# and this output may end up pasted somewhere.
$stored = dotnet user-secrets list --project $project 2>$null

Write-Host ''
Write-Host 'Stored:' -ForegroundColor Green

foreach ($line in $stored) {
    if ($line -match '^(?<key>[^=]+)=\s*(?<value>.*)$') {
        $key = $Matches['key'].Trim()
        $value = $Matches['value'].Trim()

        if ($key -like '*Secret*') {
            Write-Host ("  {0} = {1}" -f $key, ('*' * 8 + " (" + $value.Length + " chars)"))
        }
        else {
            Write-Host ("  {0} = {1}" -f $key, $value)
        }
    }
}

if (Test-Path $backup) {
    Write-Host ''
    Write-Host "$(Split-Path -Leaf $backup) still holds the secret in plain text." -ForegroundColor Yellow
    $answer = Read-Host 'Delete it now? (y/n)'

    if ($answer -eq 'y') {
        Remove-Item $backup -Force
        Write-Host 'Deleted.' -ForegroundColor Green
    }
}

Write-Host ''
Write-Host 'Now start the server with no arguments:' -ForegroundColor Cyan
Write-Host '  .\scripts\run-local-oauth.ps1'
Write-Host ''
Write-Host 'To remove them later:  .\scripts\set-secrets.ps1 -Clear' -ForegroundColor DarkGray
Write-Host ''
