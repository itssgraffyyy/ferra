$ErrorActionPreference = "Continue"
$out = "g:\project\p3_check2.txt"
"" | Set-Content $out -Encoding UTF8
function Log([string]$t) { Add-Content -Path $out -Value $t -Encoding UTF8 }
Set-Location g:\project
Log "=== python version ==="
Log (python --version 2>&1 | Out-String)
Log "=== ml deps ==="
python -c "import sklearn, numpy, joblib, pandas, scipy; import sklearn as s; print('sklearn', s.__version__); print('numpy', numpy.__version__); print('joblib', joblib.__version__); print('pandas', pandas.__version__); print('scipy', scipy.__version__)" 2>&1 | ForEach-Object { Log "$_" }
Log "=== pytest baseline (full run) ==="
$p = python -m pytest -q --no-header 2>&1 | Out-String
Log $p
Log "=== DONE ==="
