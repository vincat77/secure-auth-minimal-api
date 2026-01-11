param(
    [string]$DbPath = "src/SecureAuthMinimalApi/auth.db",
    [string]$Username = "unconfirmed",
    [string]$Password = "Unconfirmed123!",
    [string]$Email    = "unconfirmed@example.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DbPath)) {
    throw "Database not found at $DbPath. Avvia l'app per farlo generare, oppure specifica il percorso corretto."
}

Add-Type -AssemblyName System.Data.SQLite

$conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DbPath;Version=3;")
$conn.Open()

# Check if user exists
$cmdCheck = $conn.CreateCommand()
$cmdCheck.CommandText = "SELECT COUNT(*) FROM users WHERE username = @u"
$cmdCheck.Parameters.AddWithValue("@u", $Username) | Out-Null
$exists = [int]$cmdCheck.ExecuteScalar()
if ($exists -gt 0) {
    Write-Host "User '$Username' already exists, skipping insert."
    $conn.Dispose()
    return
}

# Generate ids and hash
$userId = [Guid]::NewGuid().ToString("N")
$now = [DateTime]::UtcNow.ToString("O")
$salt = [Guid]::NewGuid().ToString("N")
# Simplified hash (match PasswordHasher in app if needed). Here use SHA256(salt+password)
$sha = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($salt + $Password)
$hash = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-","").ToLower()

$cmd = $conn.CreateCommand()
$cmd.CommandText = @"
INSERT INTO users (id, username, username_normalized, email, email_normalized, password_hash, password_salt, email_confirmed_at_utc, created_at_utc)
VALUES (@id, @u, LOWER(@u), @e, LOWER(@e), @h, @s, NULL, @now)
"@
$cmd.Parameters.AddWithValue("@id", $userId) | Out-Null
$cmd.Parameters.AddWithValue("@u", $Username) | Out-Null
$cmd.Parameters.AddWithValue("@e", $Email) | Out-Null
$cmd.Parameters.AddWithValue("@h", $hash) | Out-Null
$cmd.Parameters.AddWithValue("@s", $salt) | Out-Null
$cmd.Parameters.AddWithValue("@now", $now) | Out-Null
$cmd.ExecuteNonQuery() | Out-Null

Write-Host "Created unconfirmed user:"
Write-Host " - username: $Username"
Write-Host " - password: $Password"
Write-Host " - email:    $Email"

$conn.Dispose()
