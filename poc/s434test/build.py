#!/usr/bin/env python3
"""Build a single self-contained HTML file from all JS dependencies."""
import os, sys, re

DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(DIR, "src")
OUT = os.path.join(DIR, "run_s434.html")

def read(fname):
    # All dependency files are in src/ subdirectory
    with open(os.path.join(SRC, fname.lstrip("./")), "r") as f:
        return f.read()

core_js = read("core.js")
mem_js = read("mem.js")
int64_js = read("int64.js")
offsets_js = read("ps4_offsets.js")
chain_js = read("chain_s434.js")

# Strip all import statements (single and multi-line)
def strip_imports(code):
    code = re.sub(r'^import\s+\{[^}]*\}\s+from\s+[\'"][^\'"]*[\'"];?\s*$', '', code, flags=re.MULTILINE|re.DOTALL)
    code = re.sub(r'^import\s+\w+\s+from\s+[\'"][^\'"]*[\'"];?\s*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'^import\s+.*$', '', code, flags=re.MULTILINE)
    return code

# Strip export statements from library files (they'll be inlined)
def strip_module(code):
    code = re.sub(r'^export\s+\{[^}]*\};?\s*$', '', code, flags=re.MULTILINE|re.DOTALL)
    code = re.sub(r'^export\s+default\s+', '', code, flags=re.MULTILINE)
    code = re.sub(r'^export\s+(?:async\s+)?function\s+', 'function ', code, flags=re.MULTILINE)
    code = re.sub(r'^export\s+const\s+', 'const ', code, flags=re.MULTILINE)
    return code

core_js = strip_module(core_js)
mem_js = strip_imports(strip_module(mem_js))
int64_js = strip_module(int64_js)
offsets_js = strip_module(offsets_js)

chain_js = strip_imports(chain_js)

html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PS4 FW13.52 -- sc#434/435 Deep Probe</title>
<style>
html,body{{margin:0;padding:0;background:#0b0d10;color:#c8ced8;font:15px/1.45 "Segoe UI",system-ui,sans-serif}}
#wrap{{padding:16px 18px}}
#state{{font-size:22px;font-weight:700;margin:0 0 10px}}
#out{{white-space:pre-wrap;font:12px/1.45 Consolas,monospace;background:#11151b;border:1px solid #1e2732;border-radius:5px;padding:10px 12px;height:calc(100vh - 80px);overflow-y:auto}}
.ok{{color:#7fd0a0}}.bad{{color:#d08a7f}}.warn{{color:#d8c07f}}
</style>
</head>
<body>
<div id="wrap">
<div id="state">loading sc#434/435 probe...</div>
<div id="out"></div>
</div>
<script>
// === int64.js (inlined) ===
{int64_js}
</script>
<script>
// === core.js (inlined) ===
{core_js}
</script>
<script>
// === mem.js (inlined) ===
{mem_js}
</script>
<script>
// === ps4_offsets.js (inlined) ===
{offsets_js}
</script>
<script>
// === chain_s434.js (inlined, imports stripped) ===
{chain_js}
</script>
</body>
</html>'''

with open(OUT, "w") as f:
    f.write(html)

print(f"Built {OUT} ({os.path.getsize(OUT)} bytes)")
print(f"  core.js:    {len(core_js)} bytes")
print(f"  mem.js:     {len(mem_js)} bytes")
print(f"  int64.js:   {len(int64_js)} bytes")
print(f"  offsets.js: {len(offsets_js)} bytes")
print(f"  chain.js:   {len(chain_js)} bytes")
