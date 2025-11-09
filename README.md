# Asset Discovery

A small C utility that reads the local OS ARP table and performs CIDR expansion to produce a list of IP addresses. The tool also optionally looks up vendor names using an OUI file (`oui.txt`) in the project root.

This repository contains:

- `src/` : C source files (`main.c`, `asset-discovery.c`).
- `include/asset-discovery.h` : public header.
- `oui.txt` : OUI database (vendor lookup).
- `CMakeLists.txt` : build configuration.

## Features

- Read the operating system ARP table and print MAC/IP/vendor information.
- Expand CIDR ranges into individual IP addresses and write them to `all_ips.txt`.

## Quick note: why some devices are missing

- The program reads your machine's ARP cache (the OS ARP table). The router UI shows the router's client list (router ARP/NAT table). These are different sets.
- An ARP entry exists on your host only after your host has communicated with that IP (sent or received traffic), or the OS resolved it recently. Mobile devices and sleeping devices may not be visible in your host ARP until they send traffic or are probed.
- Guest Wi‑Fi / client isolation can prevent your host from seeing other clients on the same SSID.

If a device is shown in the router UI but not on your host, it's usually because your host never ARP-resolved that IP yet.

## Populate the ARP cache (ping sweep)

Run a ping sweep to force your machine to send ARP requests and populate its ARP table. After the sweep, run the program again to see newly discovered entries.

Linux (bash):
```bash
for i in {1..254}; do
  ping -c 1 -W 1 192.168.0.$i >/dev/null 2>&1 &
done
wait
arp -a
```

macOS (bash / zsh):
```bash
# macOS ping timeouts differ; a plain quick ping per host works fine
for i in {1..254}; do
  ping -c 1 192.168.0.$i >/dev/null 2>&1 &
done
wait
arp -a
```

Windows (PowerShell):
```powershell
1..254 | ForEach-Object { ping -n 1 -w 100 192.168.0.$_ > $null }
arp -a
```

Windows (cmd.exe):
```cmd
for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.0.%i >nul
arp -a
```

Or use `nmap` for a better local-network discovery (performs ARP pings):
```bash
# install nmap if you don't have it (Homebrew on macOS, your distro package manager on Linux)
brew install nmap
nmap -sn 192.168.0.0/24
arp -a
```

After running any of the above sweeps, re-run the tool (see Run section) and the OS ARP cache should now include many responsive hosts.

## Build

Prerequisites:

- C compiler (GCC/Clang on macOS/Linux, MSVC or MinGW-w64 on Windows)
- `cmake` (version >= 3.10 recommended)
- `make` / `ninja` / or Visual Studio build tools depending on platform

General (cross-platform) CMake flow:
```bash
mkdir -p build
cd build
cmake ..
cmake --build . --config Debug
# resulting binary: build/asset-discovery (or asset-discovery.exe on Windows)
```

### Linux / macOS (GCC or Clang)

From a POSIX shell:
```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j$(nproc || sysctl -n hw.ncpu)
```

If `cmake` selects Visual Studio on Windows by default, pass an explicit generator as shown in the Windows section.

### Windows (MSVC)

Open the "Developer Command Prompt for Visual Studio" and run:
```powershell
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Debug
# or open the generated .sln in Visual Studio
```

Replace the generator name with your installed VS version if needed (for example, "Visual Studio 16 2019").

### Windows (GCC via MinGW-w64)

From a MinGW shell or MSYS2 environment:
```bash
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make -j4
```

## Run

Usage:
```bash
# from project root
./build/asset-discovery 192.168.0.0/24

# on Windows (PowerShell)
.\build\asset-discovery.exe 192.168.0.0/24
```

Notes:

- The program attempts to load `./oui.txt` for OUI (vendor) lookups. If `oui.txt` is missing or cannot be parsed, vendor lookups will be skipped (you'll see a warning).
- The tool reads the OS ARP table via `ip neigh` / `arp -n` on Linux, `arp -a` on macOS, and `arp -a` on Windows. It does not actively probe the network unless you run the suggested ping sweep or use a network scanner.

## Optional: automatically populate ARP cache

If you want the tool itself to trigger ARP population, you can modify `main.c` to perform a quick ping sweep of the expanded CIDR before calling `get_arp_entries()`. This is optional because active probing may be noisy or unwanted on some networks.

If you'd like, I can implement this change for you — tell me whether you want a) a simple sequential sweep, b) a parallel sweep with limited concurrency, or c) a user-controlled flag (e.g. `--probe`) that enables the sweep.

## Troubleshooting & tips

- If some devices still don't show up after a sweep, they may be asleep, using MAC randomization, or separated by AP isolation / VLANs.
- Use the router's admin UI to confirm device IP/MAC if needed — that's the router's view, not your host's ARP.
- For more complete discovery on local networks, `nmap -sn` is recommended because it uses ARP pings for local Ethernet networks and is robust.

