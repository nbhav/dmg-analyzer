# dmg-analyzer

Static security analysis for macOS DMG files. Runs entirely inside an isolated
container with no network access. DMG is piped in via stdin — no bind mount
on the input side.

## Requirements

- macOS 26+ (Apple Silicon) — uses `container` CLI
- Or: Docker on any platform (swap `container` for `docker` in `analyze.sh`)

## Setup

```bash
# Build the container image
container build -t dmg-analyzer .

# Or with Docker:
docker build -f Containerfile -t dmg-analyzer .
```

## Usage

```bash
chmod +x analyze.sh
./analyze.sh ~/Downloads/SomeApp.dmg
```

Output lands in `./output/<AppName>/`.

## Output files

| File | Contents |
|------|----------|
| `00_bundle_structure.json` | Bundle layout, executables, auto-update config |
| `01_binary_info.json` | Architectures, linked libs, binary protections |
| `02_code_signing.json` | Signature, entitlements, sensitive permissions |
| `03_plist_audit.json` | All plist files, hardcoded values, URLs |
| `04_secrets.json` | Hardcoded credentials and API keys |
| `05_endpoints.json` | Network endpoints, tracking services, AI APIs |
| `06_frameworks.json` | Known SDK fingerprints, risk categorization |
| `07_strings.txt` | Raw strings from all executables |
| `summary.json` | Rolled-up findings, risk score, LLM-ready |
| `summary.md` | Human-readable markdown summary |

## Feeding into an LLM

`summary.json` is structured for direct LLM ingestion. For deeper analysis,
feed in the individual module files alongside it.

```bash
# Example: pipe summary to Claude via CLI
cat output/MyApp/summary.json | claude "Analyze these security findings and identify the highest priority risks"
```

## Security model

- DMG enters via stdin — no host filesystem mount on the input side
- Output bind mount is the only host exposure (write path only from container)
- `--network none` — container has zero network egress
- Non-root user inside container
- Decompression bomb check before extraction
- Path traversal check before extraction  
- Symlink audit and neutralization before any analysis script runs

## Adding modules

Each module follows the same contract:
```python
def analyze(extract_dir: str, output_path: str) -> None:
    # read from extract_dir
    # write JSON to output_path
```

Add the script to `src/`, add a `run_module` call in `scripts/run_all.sh`.
