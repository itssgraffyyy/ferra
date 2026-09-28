$ErrorActionPreference = "Continue"
$o = "g:\project\p3_inspect.txt"
Set-Location g:\project
"BEGIN" | Set-Content $o
"---STATUS---" >> $o
git --no-pager status --porcelain -b 2>&1 | Out-String | Add-Content $o
"---LOG---" >> $o
git --no-pager log --oneline -8 2>&1 | Out-String | Add-Content $o
"---REMOTE---" >> $o
git --no-pager remote -v 2>&1 | Out-String | Add-Content $o
"---BRANCH---" >> $o
git branch --show-current 2>&1 | Out-String | Add-Content $o
"---DEPS---" >> $o
python -c "import importlib.util as u; names=('sklearn','numpy','joblib','pandas','matplotlib'); print({n: bool(u.find_spec(n)) for n in names})" 2>&1 | Out-String | Add-Content $o
"---PYVER---" >> $o
python --version 2>&1 | Out-String | Add-Content $o
"---DOCS---" >> $o
Get-ChildItem docs -Name -ErrorAction SilentlyContinue | Out-String | Add-Content $o
"---DATA---" >> $o
Get-ChildItem data -Recurse -Depth 2 -Name -ErrorAction SilentlyContinue | Select-Object -First 60 | Out-String | Add-Content $o
"---GITIGNORE---" >> $o
Get-Content .gitignore -ErrorAction SilentlyContinue | Out-String | Add-Content $o
"---TESTS---" >> $o
Get-ChildItem tests -Name -ErrorAction SilentlyContinue | Out-String | Add-Content $o
"SENTINEL_DONE" >> $o
