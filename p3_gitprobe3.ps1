$ErrorActionPreference = "Continue"
$out = "g:\project\p3_gitprobe3.txt"
Set-Location g:\
"" | Set-Content $out -Encoding UTF8
function Log([string]$t) { Add-Content -Path $out -Value $t -Encoding UTF8 }
Log "=== COMMIT_EDITMSG ==="
Log (Get-Content G:\.git\COMMIT_EDITMSG -ErrorAction SilentlyContinue | Out-String)
Log "=== object count ==="
Log ((Get-ChildItem -Recurse -File G:\.git\objects -ErrorAction SilentlyContinue | Measure-Object).Count)
Log "=== fetch origin ==="
$f = git fetch origin 2>&1 | Out-String; Log $f
Log "=== remote refs ==="
Log (git for-each-ref 2>&1 | Out-String)
Log "=== log origin/main ==="
Log (git --no-pager log --oneline origin/main -15 2>&1 | Out-String)
Log "=== ls-tree origin/main ==="
Log (git ls-tree --name-only origin/main 2>&1 | Out-String)
Log "=== DONE ==="
