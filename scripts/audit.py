"""Mechanical production-readiness checks over the source tree."""

import pathlib
import re

SRC = pathlib.Path("src")


def source_files():
    for path in SRC.rglob("*.cs"):
        parts = set(path.parts)
        if "obj" in parts or "bin" in parts:
            continue
        yield path


def section(title):
    print()
    print(f"=== {title} ===")


section("catch blocks that neither log, rethrow, nor return")
found = False
for path in source_files():
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not re.search(r"\bcatch\b", line):
            continue
        block = "\n".join(lines[index : index + 7])
        if not re.search(r"Log[A-Z]|throw|return|_logger", block):
            print(f"  {path}:{index + 1}  {line.strip()}")
            found = True
if not found:
    print("  none")


section("hardcoded credentials or connection strings")
patterns = [
    (r'password\s*=\s*"[^"]{3,}"', "password literal"),
    (r'secret\s*=\s*"[^"]{8,}"', "secret literal"),
    (r"AccountKey=", "storage key"),
    (r"eyJ[A-Za-z0-9_-]{20,}", "embedded JWT"),
]
found = False
for path in source_files():
    text = path.read_text(encoding="utf-8")
    for pattern, label in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            print(f"  {path}  {label}: {match.group()[:60]}")
            found = True
if not found:
    print("  none")


section("non-Microsoft hosts referenced in code")
hosts = set()
for path in source_files():
    for match in re.finditer(r"https://([a-z0-9.-]+)", path.read_text(encoding="utf-8")):
        host = match.group(1)
        if not host.endswith(("microsoft.com", "microsoftonline.com", "sharepoint.com",
                              "1drv.com", "svc.ms", "onedrive.com", "modelcontextprotocol.io",
                              "graph.microsoft.com")):
            hosts.add(host)
for host in sorted(hosts):
    print(f"  {host}")
if not hosts:
    print("  none")


section("shared mutable state and its guards")
for path in source_files():
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"private\s+(?:readonly\s+)?(?:static\s+)?(\w+<[^>]+>|\w+)\s+(_\w+)\s*=", text):
        kind, name = match.group(1), match.group(2)
        if any(k in kind for k in ("Dictionary", "List", "HashSet", "Queue")):
            guarded = "Concurrent" in kind or "lock" in text or "Lock" in kind
            marker = "ok" if guarded else "UNGUARDED"
            print(f"  {marker:10} {path.name}: {kind} {name}")


section("IDisposable types and whether Dispose is implemented")
for path in source_files():
    text = path.read_text(encoding="utf-8")
    if "IDisposable" in text and "class" in text:
        implemented = "public void Dispose()" in text
        name = path.stem
        print(f"  {'ok' if implemented else 'MISSING':10} {name}")


section("options validated at startup")
for path in source_files():
    text = path.read_text(encoding="utf-8")
    if "AddOptions<" in text:
        for match in re.finditer(r"AddOptions<(\w+)>", text):
            validated = "ValidateOnStart" in text
            print(f"  {'validated' if validated else 'NOT VALIDATED':14} {match.group(1)}")


section("production guards in the host")
program = (SRC / "OneDriveMcp.Server" / "Program.cs").read_text(encoding="utf-8")
for label, pattern in [
    ("refuses dev token in Production", r"Dev:GraphAccessToken is set in Production"),
    ("refuses anonymous MCP in Production", r"EnableOAuth is false in Production"),
    ("MCP endpoint requires authorization", r"RequireAuthorization"),
    ("HTTPS redirect outside Development", r"UseHttpsRedirection"),
    ("HSTS outside Development", r"UseHsts"),
    ("request body size capped", r"MaxRequestBodySize"),
    ("Kestrel server header suppressed", r"AddServerHeader = false"),
]:
    print(f"  {'yes' if re.search(pattern, program) else 'NO':4}  {label}")
