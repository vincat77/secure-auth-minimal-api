param(
    [string]$BaseUrl = "https://localhost:52899",
    [string]$Username = "demo",
    [string]$Password = "123456789012",
    [switch]$ShowBodies
)

$ErrorActionPreference = "Stop"

# Bypass self-signed certs on older PowerShell (no -SkipCertificateCheck)
$originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Write-Step($message) {
    Write-Host "==> $message"
}

function Invoke-JsonPost {
    param(
        [string]$Uri,
        [hashtable]$Body,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [hashtable]$Headers
    )

    return Invoke-WebRequest -Method Post -Uri $Uri `
        -ContentType "application/json" `
        -Body (ConvertTo-Json $Body) `
        -WebSession $Session `
        -Headers $Headers
}

# 1) Health check
Write-Step "Health check $BaseUrl/health"
$health = Invoke-WebRequest -Method Get -Uri "$BaseUrl/health"
Write-Host "Health status: $($health.StatusCode)"

# Prepare session for cookies
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# 2) Login (remember=true)
Write-Step "Login as $Username (remember=true)"
$loginBody = @{
    username   = $Username
    password   = $Password
    rememberMe = $true
}

$loginResp = Invoke-JsonPost -Uri "$BaseUrl/login" -Body $loginBody -Session $session -Headers @{}
Write-Host "Login status: $($loginResp.StatusCode)"

$loginJson = $loginResp.Content | ConvertFrom-Json
$accessCsrf = $loginJson.csrfToken
if ($ShowBodies) {
    Write-Host "Login body:" ($loginResp.Content)
}

# Extract refresh CSRF token
$refreshCsrf = $loginJson.refreshCsrfToken
if (-not $refreshCsrf) {
    throw "refreshCsrfToken missing in login response."
}
Write-Host "refreshCsrfToken: $refreshCsrf"
Write-Host "access CSRF token: $accessCsrf"

# Show cookies snapshot
Write-Host "Cookies set:"
$session.Cookies.GetCookies($BaseUrl) | ForEach-Object {
    Write-Host " - $($_.Name) (Secure=$($_.Secure); HttpOnly=$($_.HttpOnly); Path=$($_.Path))"
}

# 3) Refresh with double-submit header
Write-Step "Refresh using X-Refresh-Csrf header"
$refreshHeaders = @{ "X-Refresh-Csrf" = $refreshCsrf }
$refreshResp = Invoke-WebRequest -Method Post -Uri "$BaseUrl/refresh" `
    -WebSession $session `
    -Headers $refreshHeaders

Write-Host "Refresh status: $($refreshResp.StatusCode)"
if ($ShowBodies) {
    Write-Host "Refresh body:" ($refreshResp.Content)
}

$refreshJson = $refreshResp.Content | ConvertFrom-Json
if ($refreshJson.refreshCsrfToken) {
    Write-Host "New refreshCsrfToken: $($refreshJson.refreshCsrfToken)"
    $refreshCsrf = $refreshJson.refreshCsrfToken
}
if ($refreshJson.csrfToken) {
    Write-Host "New access CSRF token: $($refreshJson.csrfToken)"
    $accessCsrf = $refreshJson.csrfToken
}

# 4) Refresh without header (expected 401/403)
Write-Step "Refresh without X-Refresh-Csrf (expected unauthorized)"
try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/refresh" `
        -WebSession $session `
        -ErrorAction Stop | Out-Null
    Write-Host "Unexpected success without header"
} catch {
    Write-Host "Status: $($_.Exception.Response.StatusCode)"
}

# 5) Refresh with wrong header (expected unauthorized)
Write-Step "Refresh with wrong X-Refresh-Csrf (expected unauthorized)"
try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/refresh" `
        -WebSession $session `
        -Headers @{ "X-Refresh-Csrf" = "wrong-token" } `
        -ErrorAction Stop | Out-Null
    Write-Host "Unexpected success with wrong header"
} catch {
    Write-Host "Status: $($_.Exception.Response.StatusCode)"
}

# 6) Logout with/without CSRF
Write-Step "Logout with CSRF header"
try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/logout" `
        -WebSession $session `
        -Headers @{ "X-CSRF-Token" = $accessCsrf } `
        -ErrorAction Stop | Out-Null
    Write-Host "Logout with CSRF: OK"
} catch {
    Write-Host "Logout with CSRF failed: $($_.Exception.Response.StatusCode)"
}

Write-Step "Logout without CSRF header (expected unauthorized)"
try {
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/logout" `
        -WebSession $session `
        -ErrorAction Stop | Out-Null
    Write-Host "Unexpected success without CSRF on logout"
} catch {
    Write-Host "Status: $($_.Exception.Response.StatusCode)"
}

# 7) Change email (requires account non-confirmato; su demo confermato restituisce email_already_confirmed)
Write-Step "Change email (requires unconfirmed account; demo è già confermato)"
$newEmail = "dev" + [guid]::NewGuid().ToString("N").Substring(0,6) + "@example.com"
try {
    $resp = Invoke-WebRequest -Method Post -Uri "$BaseUrl/me/email" `
        -WebSession $session `
        -Headers @{ "X-CSRF-Token" = $accessCsrf } `
        -ContentType "application/json" `
        -Body (ConvertTo-Json @{ newEmail = $newEmail }) `
        -ErrorAction Stop
    Write-Host "Change email status: $($resp.StatusCode)"
    if ($ShowBodies) { Write-Host "Change email body:" ($resp.Content) }
} catch {
    Write-Host "Change email failed (atteso su demo confermato): $($_.Exception.Response.StatusCode)"
}

Write-Host ""
Write-Host "Done. Session cookies available in `$session for further calls."

# Restore cert callback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
