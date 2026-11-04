Shah Tunnel prebuilt Linux binary capsule
Version: 2.1.0
Binary: ravanreverse
Target: linux/amd64 (x86_64)

Files in this folder:
  main.go       - Go source code
  main_test.go  - tests
  ravanreverse  - statically linked Linux amd64 executable
  SHA256SUMS    - SHA-256 checksum for ravanreverse

The executable is placed directly beside main.go. No architecture
subfolders are used in this single-binary layout.

The S1T-START.sh installer downloads the binary and checksum from:
  https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-CAPSULE/

The installer verifies SHA-256 and checks the binary-reported application
version and architecture before installing it. This one-file build supports
Linux amd64/x86_64 only. Linux arm64/aarch64 needs a separately compiled
binary; it cannot run this amd64 executable.

To install from a local source checkout, run as root from the repository root:
  bash S1T-START.sh

To install remotely after pushing the files to the main branch:
  bash <(curl -fsSL https://raw.githubusercontent.com/ShahNetLab/ShahTunnel/main/S1T-START.sh)
