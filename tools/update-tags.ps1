# Regenerate ctags index for this repo
param(
    [string]$TagsFile = "tags"
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$ctagsExe = Join-Path $root "tools\ctags\ctags.exe"
if (-not (Test-Path $ctagsExe)) {
    throw "ctags.exe not found at $ctagsExe. Download universal-ctags x64 into tools\ctags first."
}

Push-Location $root
try {
    & $ctagsExe -R --languages=C# --exclude=.git --exclude=bin --exclude=obj -f $TagsFile
}
finally {
    Pop-Location
}
