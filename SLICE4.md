# SLICE 4 — Wire services into the app: glass-box + triage hub UI (level9000)

## Contract
- **Goal:** Make the three new services reachable from the browser and visible to an analyst:
  proxy investigator/triage/root-cause through web-server, and surface (a) the glass-box reasoning
  trace for an investigation and (b) the triage queue in the existing SOC console.
- **Acceptance:**
  BACKEND (vitest, deterministic):
  1. New proxy routes on web-server: `POST /api/v1/investigate` → investigator `/investigate`;
     `GET /api/v1/runs/:id` → investigator (or root-cause) `/runs/:id`; `GET /api/v1/triage/queue`,
     `POST /api/v1/triage/:id/investigate`, `GET /api/v1/triage/:id`, `POST /api/v1/triage/:id/transition`
     → triage service. Each forwards method+body+query, returns upstream status+JSON, 502 on upstream down.
  2. Routes are registered like registerChatRoutes; unit-tested with a mocked fetch (match chat.test.ts style):
     assert the proxy calls the right upstream URL + method and passes body/params through; upstream 5xx → 502.
  3. New env: INVESTIGATOR_URL, TRIAGE_URL, ROOT_CAUSE_URL (defaults http://<svc>:<port>).
  FRONTEND (screenshot):
  4. A "Glass Box" panel: given a run_id, fetches /api/v1/runs/:id and renders the ordered trace steps
     (plan → tool_call/tool_result → verdict → synthesis) as a readable timeline (event type + key data).
  5. A "Triage" view/tab: fetches /api/v1/triage/queue and renders alerts grouped by bucket with severity,
     signature, count; a button to run investigate on an alert; shows resulting verdict bucket.
  6. The existing chat surface still works (no regression to sendQuery/pollJob/alert feed).
- **Done:** vitest green (existing + new proxy tests); web-server builds; frontend rendered and
  screenshot-verified against a live (compose) stack with seeded data; existing python acid still 82 green.

## Architecture
- BACKEND: new `packages/web-server/src/api/proxy.ts` exporting `registerProxyRoutes(server)`, registered
  in index.ts next to registerChatRoutes. Thin fetch forwarder + a small helper `proxyJson(url, method, body?)`.
  Reuse the existing security posture (routes are same-origin, session cookie already applied globally).
- FRONTEND: SURGICAL additions to static/index.html — do NOT rewrite. Add: a collapsible "Glass Box"
  panel in the response area that appears when a response carries a run_id (or via a "view trace" affordance),
  and a "Triage" tab toggling the main pane between Chat and Triage Queue. Keep the existing dark NOC theme,
  CSS variables, and vanilla-JS style (no framework). Match existing fetch/render idioms (renderData etc.).

## Verification
- Backend: `npm run test --workspace=packages/web-server` (vitest). Add proxy.test.ts.
- Frontend: bring up compose (postgres+investigator+triage+web-server+nginx OR just web-server with the
  service URLs pointing at running containers), seed a couple alerts + one investigation run directly via
  the python services, then drive a headless browser to screenshot the Triage view and a Glass Box trace.
  Use the `run`/`frontend` skills or a Playwright one-shot. Compare visually; iterate until it reads clean.

## Model routing: sonnet-5 for proxy (mechanical) + frontend (needs design judgment). Screenshot review by me.
## Writing: README/UI copy per harness §8 — no em dashes, plain microcopy ("View trace", "Run triage").
