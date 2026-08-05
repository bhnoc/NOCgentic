# Shadow the Hunter — MUD infrastructure

Branching forensic MUD tours built from real curated hunt packages.

## Ports

| Port | Service | URL |
|------|---------|-----|
| **3100** | Hub | http://localhost:3100 |
| **3106** | #06 Host Sweep FP MUD (V1) | http://localhost:3106 |
| **3107** | ELI5 API (optional profile) | http://localhost:3107/health |
| **3108** | #07 Spike DNS TP Learning MUD (V2) | http://localhost:3108 |

## Start

From repo root (Docker Desktop running):

```powershell
# Core MUDs + hub
docker compose -f docs/mocks/docker-compose.mud.yml up -d

# Optional AI select→ELI5 (needs GEMINI_API_KEY / .env.s3)
docker compose -f docs/mocks/docker-compose.mud.yml --profile eli5 up -d
```

Stop:

```powershell
docker compose -f docs/mocks/docker-compose.mud.yml down
```

## Layout

```
docs/mocks/
  hub/                      # Compare hub (links to MUD tours)
  06-shadow-hunter/         # FP branching MUD + rewind
  07-spike-dns-tp/          # TP learning MUD V2 (skills + reflection)
  shadow-packages/          # Curated hunt packages (tokenized)
  docker-compose.mud.yml    # This stack
  shared/                   # Shared theme/facts helpers

docs/SHADOW-THE-HUNTER-DESIGN.md
```

## Packages

| Package | Tour | Story |
|---------|------|--------|
| `sth-20260801-host-sweep-fp` | :3106 | False positive — Host Sweep / public DNS |
| `sth-20260801-spike-dns-tp` | :3108 | True positive — Spike DNS malware sole-source |

Operator-only `redaction-map.json` files are gitignored — never commit originals.

## Golden paths

- **FP:** G0→G5 all choice `1` → Clean first pass  
- **TP:** G0→G6 all choice `1` after board → Method locked in (6 skills)

Keys: `1`/`2`/`3` · `R` rewind last decision · breadcrumb **↩ Change decision**
