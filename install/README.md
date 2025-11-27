# SentinelOne Agent Installation

Place SentinelOne agent deb files in install directory.

## Directory Structure

```
install/
├── aarch64/    # ARM64 (Apple Silicon)
│   └── SentinelAgent*.deb
└── x86_64/     # Intel/AMD
    └── SentinelAgent*.deb
```

## Usage

1. Copy SentinelOne deb to appropriate directory:
   ```bash
   cp SentinelAgent*.deb install/aarch64/  # or x86_64/
   ```

2. Build with SentinelOne (default):
   ```bash
   make build
   ```

3. Build without SentinelOne:
   ```bash
   INSTALL_SENTINELONE=0 make build
   ```

## Notes

- Files are .gitignored for security
- Build script auto-detects architecture
