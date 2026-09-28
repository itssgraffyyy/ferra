$ErrorActionPreference = "Continue"
$out = "g:\project\p3_check.txt"
Set-Location g:\project
"" | Set-Content $out -Encoding UTF8
function Log([string]$t) { Add-Content -Path $out -Value $t -Encoding UTF8 }
Log "=== toplevel ==="
$t = git rev-parse --show-toplevel 2>&1 | Out-String; Log $t
Log "=== gitdir ==="
$g = git rev-parse --git-dir 2>&1 | Out-String; Log $g
Log "=== status ==="
$s = git --no-pager status --porcelain -b 2>&1 | Out-String; Log $s
Log "=== log ==="
$l = git --no-pager log --oneline -8 2>&1 | Out-String; Log $l
Log "=== remote ==="
$r = git --no-pager remote -v 2>&1 | Out-String; Log $r
Log "=== gitignore-check ==="
Log (Test-Path g:\project\.git)
Log (Test-Path g:\.git)
Log "=== pytest ==="
$p = python -m pytest --version 2>&1 | Out-String; Log $p
Log "=== pip ==="
$pp = python -m pip --version 2>&1 | Out-String; Log $pp
Log "=== DONE ==="
