<#
    The page the browser lands on after the OAuth redirect.

    Shared by tool.ps1 and test-all.ps1 via dot-sourcing, so both show the same thing. Inline
    styles only, no external resources, and it follows the operating system's light or dark
    setting. Its only job is to tell the person the browser is finished with them.
#>

function Get-CallbackPageHtml {
    param(
        [Parameter(Mandatory)] [ValidateSet('Success', 'Failure')] [string] $Outcome,
        [string] $Detail
    )

    $isSuccess = $Outcome -eq 'Success'

    $accent = if ($isSuccess) { '#12873f' } else { '#b42318' }
    $accentDark = if ($isSuccess) { '#48c07a' } else { '#f87066' }

    $icon = if ($isSuccess) {
        '<path d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4L9 16.2Z"/>'
    }
    else {
        '<path d="M19 6.4 17.6 5 12 10.6 6.4 5 5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12 19 6.4Z"/>'
    }

    $heading = if ($isSuccess) { 'Signed in' } else { 'Sign-in failed' }

    $message = if ($isSuccess) {
        'You can close this tab. The terminal has taken over from here.'
    }
    else {
        'Nothing was authorized. Return to the terminal for details.'
    }

    $detailBlock = if ([string]::IsNullOrWhiteSpace($Detail)) {
        ''
    }
    else {
        $encoded = [System.Net.WebUtility]::HtmlEncode($Detail)
        "      <p class=`"detail`">$encoded</p>"
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>$heading</title>
  <style>
    :root {
      --bg: #f4f5f7; --surface: #ffffff; --border: #e3e5e8;
      --text: #16181d; --text-muted: #5c6270; --accent: $accent;
      --shadow: 0 1px 2px rgba(16,24,40,.04), 0 8px 24px rgba(16,24,40,.08);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #16181d; --surface: #1e2128; --border: #2f333c;
        --text: #f2f3f5; --text-muted: #a0a6b4; --accent: $accentDark;
        --shadow: 0 1px 2px rgba(0,0,0,.3), 0 8px 24px rgba(0,0,0,.4);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 24px; background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 16px; line-height: 1.5; -webkit-font-smoothing: antialiased;
    }
    .card {
      width: 100%; max-width: 400px; text-align: center;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; box-shadow: var(--shadow); padding: 40px 32px;
    }
    .mark {
      width: 48px; height: 48px; margin: 0 auto 20px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      background: var(--accent);
    }
    .mark svg { width: 26px; height: 26px; fill: #fff; }
    h1 { margin: 0 0 8px; font-size: 20px; font-weight: 600; letter-spacing: -.01em; }
    p { margin: 0; color: var(--text-muted); font-size: 15px; }
    .detail {
      margin-top: 16px; padding: 12px 14px; border-radius: 8px;
      background: var(--bg); border: 1px solid var(--border);
      font-size: 13px; text-align: left; word-break: break-word;
    }
    @media (max-width: 420px) { .card { padding: 32px 22px; border-radius: 12px; } }
  </style>
</head>
<body>
  <main class="card">
    <div class="mark" aria-hidden="true"><svg viewBox="0 0 24 24">$icon</svg></div>
    <h1>$heading</h1>
    <p>$message</p>
$detailBlock
  </main>
</body>
</html>
"@
}
