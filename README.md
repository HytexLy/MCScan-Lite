# MCScan-Lite

Lightweight proxy-backed scanner for Minecraft server discovery (default port 25565). 
It pings targets, checks reachability through per-worker proxies, and can verify Java Edition servers via the bundled Python mcstatus helper.

## Features
- SOCKS5 or HTTP CONNECT proxy per worker
- Scan IPv4 ranges or explicit target lists/files
- Optional Minecraft status probe via Python mcstatus
- Windows GUI when launched without args

## Requirements
- C++17 compiler (MSVC, clang, or MinGW)
- Windows for the GUI; CLI builds are cross-platform but only Windows is tested
- Python 3 plus `mcstatus` for server status checks (`pip install mcstatus`)

## Build
Use the helper script (auto-detects a compiler):
```
compile_scanner.bat
```
Manual example with MinGW g++:
```
g++ scanner.cpp -std=c++17 -O2 -o scanner.exe -lws2_32 -lcomctl32 -luser32 -lgdi32
```

## Usage
Launch the Windows GUI (default):
```
scanner.exe
```
CLI example (range scan):
```
scanner.exe --start-ip 1.2.3.0 --end-ip 1.2.3.255 --proxies-file mullvadproxyips.txt --workers 64
```
CLI example (file scan):
```
scanner.exe --target-file targets.txt --proxy-type http --verbose
```
Show CLI help:
```
scanner.exe --help
```

## Proxy list format
`mullvadproxyips.txt` is a simple list of proxy IPs, one per line.

## Python status helper
The scanner calls `mcstatus_probe.py` to confirm Minecraft servers. You can override:
- `PYTHON_CMD` to select a different python executable
- `MCSTATUS_SCRIPT` to point at a custom helper path
