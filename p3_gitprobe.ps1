$ErrorActionPreference = "Continue"
$out = "g:\project\p3_gitprobe.txt"
Set-Location g:\
"" | Set-Content $out -Encoding UTF8
function Log([string]$t) { Add-Content -Path $out -Value $t -Encoding UTF8 }
Log "=== branches -a ==="
Log (git branch -a 2>&1 | Out-String)
Log "=== log --all ==="
Log (git --no-pager log --all --oneline -12 2>&1 | Out-String)
Log "=== reflog ==="
Log (git --no-pager reflog -12 2>&1 | Out-String)
Log "=== config ==="
Log (git config --local --list 2>&1 | Out-String)
Log "=== worktree list ==="
Log (git worktree list 2>&1 | Out-String)
Log "=== g-project-git ==="
Log (Test-Path g:\project\.git)
Log "=== packed-refs ==="
Log (Get-Content G:\.git\packed-refs -ErrorAction SilentlyContinue | Out-String)
Log "=== refs ==="
Log (Get-ChildItem -Recurse G:\.git\refs -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } | Out-String)
Log "=== HEAD ==="
Log (Get-Content G:\.git\HEAD -ErrorAction SilentlyContinue | Out-String)
Log "=== DONE ==="
