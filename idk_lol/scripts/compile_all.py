import py_compile
import os

base = "g:/idk_lol/backend/app"
files = []
for root, dirs, fs in os.walk(base):
    for f in fs:
        if f.endswith(".py"):
            files.append(os.path.join(root, f))

fail = 0
for f in sorted(files):
    try:
        py_compile.compile(f, doraise=True)
    except py_compile.PyCompileError as e:
        print("FAIL:", f, e)
        fail += 1

print("Compiled", len(files), "files, failures:", fail)