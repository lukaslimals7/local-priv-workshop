#!/usr/bin/env python3
"""Static checks for winpriv.bat. Parses only; never executes anything."""
import hashlib
import re
import sys
from collections import OrderedDict

path = sys.argv[1]
src = open(path, encoding="utf-8", errors="replace").read()
lines = src.splitlines()

# ---------------------------------------------------------------- labels
labels = set()
for ln in lines:
    m = re.match(r"^\s*:([A-Za-z0-9_]+)\s*$", ln)
    if m:
        labels.add(m.group(1).lower())

refs = []
for i, ln in enumerate(lines, 1):
    for m in re.finditer(r"\bgoto\s+:?([A-Za-z0-9_]+)", ln, re.I):
        refs.append((i, m.group(1).lower(), ln.strip()))
    for m in re.finditer(r"\bcall\s+:([A-Za-z0-9_]+)", ln, re.I):
        refs.append((i, m.group(1).lower(), ln.strip()))

missing = [(i, t, l) for (i, t, l) in refs if t != "eof" and t not in labels]
print(f"labels defined : {len(labels)}")
print(f"references     : {len(refs)}")
if missing:
    print("MISSING TARGETS:")
    for i, t, l in missing:
        print(f"  line {i}: :{t}  <- {l[:90]}")
else:
    print("missing targets: none")

# ------------------------------------------------------- paren balance
def strip_strings(s):
    out, q = [], None
    for ch in s:
        if q:
            if ch == q:
                q = None
            out.append(" ")
        elif ch in "\"'":
            q = ch
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)

depth = 0
problems = []
for i, ln in enumerate(lines, 1):
    body = ln.strip()
    if body.lower().startswith(("echo(", "echo (")):
        body = body[5:]
    elif body.lower().startswith("rem ") or body.startswith("::"):
        continue
    s = strip_strings(body)
    # ignore escaped parens
    s = s.replace("^(", "").replace("^)", "")
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                problems.append((i, "unmatched )", ln.strip()[:90]))
                depth = 0
print(f"paren depth at EOF: {depth}")
if depth != 0:
    problems.append((len(lines), f"unclosed ( depth={depth}", ""))
if problems:
    print("PAREN PROBLEMS:")
    for i, why, l in problems[:20]:
        print(f"  line {i}: {why}  {l}")
else:
    print("paren problems  : none")

# ------------------------------------------------- :: comments inside blocks
depth = 0
bad = []
for i, ln in enumerate(lines, 1):
    body = ln.strip()
    s = strip_strings(body)
    if s.startswith("::") and depth > 0:
        bad.append((i, body[:80]))
    s = s.replace("^(", "").replace("^)", "")
    if body.lower().startswith("echo("):
        continue
    depth += s.count("(") - s.count(")")
    if depth < 0:
        depth = 0
print(f":: inside block : {len(bad)} (batch treats these as unsafe labels)")
for i, l in bad:
    print(f"  line {i}: {l}")

# ------------------------------------------------------- payload integrity
groups = OrderedDict()
cur = None
for ln in lines:
    m = re.match(r"\s*if !original_file! == (\S+) \(", ln)
    if m:
        cur = m.group(1)
        groups.setdefault(cur, [])
        continue
    if re.match(r"\s*\)\s*else\s*\(", ln):
        cur = "ELSE(binary family)"
        groups.setdefault(cur, [])
        continue
    m = re.match(r'\s*echo\|set /p="([0-9a-fA-F]+)"', ln)
    if m and cur:
        groups[cur].append(m.group(1))

expected = {
    "dllhijackservice.exe": "fa6e050321f433af0e486acf88eefe32",
    "Unattend.xml": "63f7269bbc53e36d2a8c323721313f9c",
    "lpe.bat": "a61df3883f400102e17894d7e6177c92",
    "savecred.bat": "5d8190e96d1b2e3230e1fd2409db81db",
    "AdminPaint.lnk": "30b7a4303bcf16936432f30ce13edbb9",
    "CleanUp.ps1": "9b8377237f5dea36d6af73e3f8f932a2",
    "ELSE(binary family)": "d62cfe23ad44ae27954d9b054296f2c3",
}

print("\npayload integrity (decoded hex -> md5):")
fails = 0
for name, chunks in groups.items():
    if not chunks:
        continue
    hexstr = "".join(chunks)
    try:
        blob = bytes.fromhex(hexstr)
    except ValueError as e:
        print(f"  {name:24s} INVALID HEX ({e})")
        fails += 1
        continue
    got = hashlib.md5(blob).hexdigest()
    exp = expected.get(name)
    state = "OK" if exp == got else ("MISMATCH" if exp else "no expected hash")
    if exp and exp != got:
        fails += 1
    print(f"  {name:24s} {len(blob):7d} bytes  {got}  {state}")

print(f"\npayload failures: {fails}")
sys.exit(0 if not missing and not problems and not fails else 1)
