$ErrorActionPreference = "Continue"
$out = "g:\project\p3_gitprobe2.txt"
Set-Location g:\
"" | Set-Content $out -Encoding UTF8
function Log([string]$t) { Add-Content -Path $out -Value $t -Encoding UTF8 }
Log "=== ls-remote origin ==="
Log (git ls-remote origin 2>&1 | Out-String)
Log "=== gitdir listing ==="
Log (Get-ChildItem G:\.git -Force -Name | Out-String)
Log "=== logs dir ==="
Log (Get-ChildItem -Recurse G:\.git\logs -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } | Out-String)
Log "=== user.name ==="
Log (git config user.name 2>&1 | Out-String)
Log "=== user.email ==="
Log (git config user.email 2>&1 | Out-String)
Log "=== global list ==="
Log (git config --global --list 2>&1 | Out-String)
Log "=== DONE ==="
