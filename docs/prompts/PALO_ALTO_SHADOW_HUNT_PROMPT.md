# Bridge: Palo Alto cortex CLI → NOCgentic Shadow the Hunter

The canonical **AI hunt prompt** lives with the investigation CLI:

`C:\Users\johnr\Documents\learning\palo_alto\prompts\SHADOW_THE_HUNTER_HUNT_PROMPT.md`

## Workflow

1. Open an AI session with shell access to `palo_alto`.
2. Paste the prompt from that file (everything under the horizontal rule / SYSTEM section as instructed).
3. Let it run a real hunt into `investigations/inv_*/`.
4. Collect `investigations/inv_*/shadow_export/`.
5. Copy that folder into NOCgentic, e.g.:

   ```text
   docs/mocks/shadow-packages/<package_id>/
   ```

6. Run sanitizer / curator pass (see `docs/SHADOW-THE-HUNTER-DESIGN.md`).
7. Build or refresh a Shadow the Hunter UI mock from the package.

## What to bring back

| File | Use in mock |
|------|-------------|
| `path.json` | Step rail |
| `shadow.json` | Toggle panel (original hunter) |
| `manifest.json` | Title, scope, tags |
| `HUNTER_NARRATIVE.md` | Debrief copy |
| `evidence/*` | Sample rows in steps |
| `redaction-map.json` | **Keep private** — build display labels only |

Do **not** commit `redaction-map.json` with real IPs/usernames into a public branch without review.
