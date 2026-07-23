---
name: ops
description: Operate and maintain the running NOCgentic (bhnocgentic) Black Hat NOC platform — start/stop the EC2 instance, renew the TLS cert, restart or debug the Docker agent stack, refresh AWS credentials, manage the security-group allow-list, update DNS, seed a re-dated "demo day" of logs so the app looks live between conferences, change the Gemini model, and smoke-test the query surface. Trigger on "start/stop the NOC server", "renew the cert", "restart the agents", "the blackhat app is down", "update the allow-list", "seed demo data", "re-date the logs to today", "make the app look live", "change the gemini model", or day-2 ops on bhnocgentic.
---

# NOCgentic — Ops Skill

Day-2 operations for the Black Hat Asia NOC platform (**bhnocgentic**, repo `bhnoc/NOCgentic`),
served at **`https://aing.bhnoc.com/`**. For first-time provisioning see [[../deploy/skill.md]].
**PostCog** (the Slack bot on the same box) is a separate app — see `blackhat/PostCog/.claude/skills/`.

Living document — append incidents, fixes, and gotchas as they happen.

## The box at a glance

| Property | Value |
|----------|-------|
| Instance ID | `i-0430224b1ac82701e` (**AING**) |
| Region | `us-west-2` |
| Type | g6e.4xlarge (GPU — **bills ~$3+/hr running**; app doesn't use the GPU) |
| App dir | `/opt/bhasia/app` |
| Compose file | `docker-compose.agents.yml` (env file: `.env.s3`) |
| DNS | `aing.bhnoc.com` (Cloudflare) → ephemeral public IP |
| Security group | `sg-022b87911ecf12539` |
| IAM role | `blackhat-pope-dev-ec2-role` |
| SSH | `ssh ubuntu@aing.bhnoc.com` (or current IP) |
| AWS profile | `VirtualPOC-users` (`-admins` for infra changes) |

> **Cost discipline:** it's a GPU box the app doesn't need. **Stop it whenever it's
> idle.** Between conferences / during dev, don't leave it running overnight.

## Golden rules

1. **The public IP changes on every stop/start** (no Elastic IP). After starting, always
   re-point the `aing.bhnoc.com` Cloudflare A record, or SSH by raw IP.
2. **Containers can't use the instance role directly.** They need AWS creds baked into
   `.env.s3` via `refresh-env-creds.sh`. Those creds **expire in hours** — the #1 cause
   of "agents suddenly can't query Athena/S3."
3. **The cert can't renew while the box is stopped.** If the instance sleeps through the
   ~60-day renewal window, the cert expires. Renew after long downtime.
4. **Never `pkill -f "python.*app.py"` on this box.** The NOCgentic `audit-monitor`
   container's main process is `python app.py` — and so is PostCog's. A broad pattern-kill
   hits both. Target containers via `docker`, not process name.

---

## Start / stop the instance

```bash
export AWS_PROFILE=VirtualPOC-users
I=i-0430224b1ac82701e; R=us-west-2

# Start
aws ec2 start-instances  --instance-ids $I --region $R
# Stop (do this when idle — saves the GPU $$)
aws ec2 stop-instances   --instance-ids $I --region $R
# State + current IP
aws ec2 describe-instances --instance-ids $I --region $R \
  --query 'Reservations[].Instances[].{State:State.Name,IP:PublicIpAddress}' --output table
```

**`InsufficientInstanceCapacity` on start:** AWS has no free g6e (GPU) capacity in the
region. It's transient. Either retry on a loop until it frees up, or (better) resize to a
CPU instance type the app actually needs. Retry loop:

```bash
for i in $(seq 1 720); do
  OUT=$(aws ec2 start-instances --instance-ids $I --region $R \
        --query 'StartingInstances[].CurrentState.Name' --output text 2>&1)
  [[ "$OUT" == pending* || "$OUT" == running* ]] && { echo "started"; break; }
  echo "[$i] no capacity, retry in 60s"; sleep 60
done
```

### After starting — re-point DNS
The IP changed. Update the `aing.bhnoc.com` A record in the Cloudflare `bhnoc.com` zone to
the new public IP. (DNS-01 cert renewal doesn't need the record, but users and SSH-by-name do.)

---

## TLS certificate

Let's Encrypt via **certbot `dns-cloudflare`** (DNS-01). Renewal config lives at
`/etc/letsencrypt/renewal/aing.bhnoc.com.conf`; Cloudflare token at
`/etc/letsencrypt/cloudflare.ini`. nginx mounts `/etc/letsencrypt` read-only.

### Check expiry
```bash
# on the box
sudo openssl x509 -in /etc/letsencrypt/live/aing.bhnoc.com/fullchain.pem -noout -dates
```

### Renew
```bash
# on the box — DNS-01, waits ~30s for propagation. Runs long; expect a pre-delay.
sudo certbot renew --cert-name aing.bhnoc.com
# force even if not near expiry:
sudo certbot renew --cert-name aing.bhnoc.com --force-renewal
```

Then **reload nginx** so it stops serving the cached (old) cert:
```bash
sudo docker exec app-nginx-1 nginx -t && sudo docker exec app-nginx-1 nginx -s reload
```

### Gotchas
- **"Another instance of Certbot is already running":** a prior run is stuck (a timed-out
  `--dry-run` is a common culprit — DNS-01 dry runs can hang). Kill it and clear locks:
  ```bash
  ps -eo pid,cmd | grep -i certbot | grep -v grep     # find PIDs
  sudo kill <pids>
  sudo rm -f /etc/letsencrypt/{,.}certbot.lock /var/lib/letsencrypt/.certbot.lock /var/log/letsencrypt/.certbot.lock
  ```
- **Non-interactive `certbot renew` adds a random pre-delay** (up to ~127s) before doing
  anything. It's not hung — wait it out. Run it backgrounded if driving via a tool with a
  short command timeout.
- **Expired because the box was off:** just renew (`--force-renewal`) then reload nginx.

---

## The Docker stack

```bash
cd /opt/bhasia/app
CF="docker-compose.agents.yml"

sudo docker compose -f $CF ps                       # status
sudo docker compose -f $CF --env-file .env.s3 up -d # (re)start
sudo docker compose -f $CF logs -f orchestrator     # follow one service's logs
sudo docker compose -f $CF restart web-server       # bounce one service
sudo docker compose -f $CF --env-file .env.s3 up -d --build --remove-orphans  # rebuild
```

Container names are `app-<service>-1` (e.g. `app-nginx-1`, `app-orchestrator-1`).
Services & ports are documented in [[../deploy/skill.md]].

### Refresh AWS credentials (do this often)
Symptom: agents return AWS auth/expired-token errors on S3 or Athena calls.
```bash
cd /opt/bhasia/app
sudo bash scripts/refresh-env-creds.sh .env.s3
sudo docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d
```

---

## Security group / access allow-list

`sg-022b87911ecf12539`. During dev it's locked to a few IPs (all protocols). In prod,
443 should be open to the audience and SSH restricted.

```bash
export AWS_PROFILE=VirtualPOC-users; SG=sg-022b87911ecf12539; R=us-west-2

# See current ingress
aws ec2 describe-security-groups --group-ids $SG --region $R \
  --query 'SecurityGroups[].IpPermissions[].{Proto:IpProtocol,From:FromPort,Cidrs:IpRanges[].CidrIp}' --output json

# Add an IP (all protocols, dev style)
aws ec2 authorize-security-group-ingress --region $R --group-id $SG \
  --ip-permissions "IpProtocol=-1,IpRanges=[{CidrIp=X.X.X.X/32,Description=whoever}]"

# Add just 443 (prod style)
aws ec2 authorize-security-group-ingress --region $R --group-id $SG \
  --protocol tcp --port 443 --cidr X.X.X.X/32

# Remove an all-protocols CIDR
aws ec2 revoke-security-group-ingress --region $R --group-id $SG \
  --ip-permissions "IpProtocol=-1,IpRanges=[{CidrIp=X.X.X.X/32}]"
```

Find your own IP: `curl -s https://checkip.amazonaws.com`.
**Never revoke the CIDR you're SSH'd in from** without a fallback (SSM/console).

### Current dev allow-list (2026-07-22)
Between conferences, dev-only. All protocols:
- `136.59.5.6/32` — James
- `208.93.179.62/32` — Spicer

(Removed at lockdown: `165.173.10.53/32` BlackHatAsia, `165.173.10.48/28`,
`86.48.10.243/32` "Spicer2", `71.229.186.132/32`. Re-add if needed.)

---

## Health checks & troubleshooting

```bash
# From an allow-listed IP
curl -s -o /dev/null -w "HTTP %{http_code}\n" https://aing.bhnoc.com/health

# On the box (bypasses SG/DNS — tests the app directly)
curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://127.0.0.1/ -H 'Host: aing.bhnoc.com'
```

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Site unreachable from outside, 200 on localhost | SG doesn't allow your IP / DNS stale | Add IP to SG; re-point Cloudflare A record |
| Browser cert error / expired | Cert lapsed (box was off) | `certbot renew --force-renewal` + reload nginx |
| Agents error on Athena/S3 | Expired temp creds in `.env.s3` | `refresh-env-creds.sh .env.s3` + `up -d` |
| One agent 502 via nginx | That container down/crashed | `docker compose ps`, `logs <svc>`, `restart <svc>` |
| `InsufficientInstanceCapacity` | No GPU capacity in region | Retry loop, or resize to CPU type |
| nginx serving old cert after renew | Not reloaded | `docker exec app-nginx-1 nginx -s reload` |
| Agent 500 after a Gemini model change | Model rejects `thinkingBudget=0` | See "Changing the Gemini model" below |

## Routine when bringing it back after downtime

1. Start instance; wait for `running`.
2. Re-point `aing.bhnoc.com` DNS to the new IP.
3. Check cert expiry; renew + reload nginx if lapsed.
4. `refresh-env-creds.sh .env.s3` (old creds are certainly expired).
5. `docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d`.
6. Verify `/health` from an allow-listed IP.
7. When done for the day: **stop the instance.**

---

## Seeding a re-dated "demo day" (make the app look live between cons)

The conference logs are frozen in the past (BH Asia = April 2026). Between events the
dashboard's "last 24h" views look empty. Fix: copy a **contiguous window** of a real
capture day and shift its timestamps to **today**, so the app queries "today" and sees
live-looking traffic. Driver: **`scripts/redate_slice.py`** (in this repo).

### How the data is laid out (know this before touching it)
- Athena DB `blackhat_pope_logs`, workgroup `blackhat-pope-dev`, region `us-west-2`. The
  `athena-hunter` / `alert-triage` agents query this DB directly (containers use temp creds
  from `.env.s3`, not the app URL).
- Tables live in bucket **`blackhat-pope-parquet`**, Hive-partitioned by **`dt=YYYY-MM-DD`**
  (the partition is the *ingestion* date, so a partition's `ts_datetime` can sprawl across
  a couple of calendar days — pick your window by inspecting `ts_datetime`, not by trusting `dt`).
- **Time columns to shift:** `ts` (epoch **double**) and `ts_datetime` (**string**
  `'%Y-%m-%d %H:%i:%s'`). Those are the only two the app reads. Other `*_time` columns
  (`http.trans_time`, `dhcp.lease_time`, `ntp.*_time`, `ocsp.*`) are durations or
  protocol-internal stamps — leave them.
- **`alerts`, `uid_lookup`, `fuid_lookup` are VIEWS** (`TableType=VIRTUAL_VIEW`) over base
  tables (`notice`, `suricata_corelight`, `conn`, `dns`, …). Do **not** copy them — they
  auto-populate once the base tables have the new partition.
- **`corelight_raw` has no `ts_datetime`** → can't be windowed; the driver copies its whole
  partition (its `ts` is still shifted). Dashboard doesn't use it; ignore or drop after.

### Run it
```bash
cd /Users/landbeforetime/Documents/dev/blackhat/NOCgentic
AWS_PROFILE=VirtualPOC-users python3 scripts/redate_slice.py            # all physical tables
AWS_PROFILE=VirtualPOC-users python3 scripts/redate_slice.py notice conn dns   # subset (test)
```
Edit the constants at the top for a new run: `SRC_DT`, `DST_DT`, `SHIFT_S`
(= days×86400), `SHIFT_D` (days as string), `WIN_FROM`/`WIN_TO`. It's **idempotent** —
drops the target `dt` partition (Glue + S3) before re-inserting, so re-running is safe.
Uses `INSERT INTO … SELECT …, '<DST_DT>' AS dt`, which writes parquet into
`s3://…/<table>/dt=<DST_DT>/` **and auto-registers the partition** (no manual `ADD PARTITION`).

### Sizing (measured 2026-07-22)
A **3-hour** window of the live BH-Asia 04-24 morning (`00:00–03:00`) → **1.70 GB**,
68 tables, ~$0.08 Athena scan, a few minutes. `conn` is ~65% of it. Rough dial: ~0.5 GB/hour.
Pick the window with a histogram first:
```sql
SELECT substr(ts_datetime,1,13) AS date_hr, COUNT(*) rows
FROM conn WHERE dt='<SRC_DT>' GROUP BY 1 ORDER BY 1;
```

### Future: bhusa26 (same recipe)
When the US 2026 data lands in the same format, this driver runs verbatim — just set
`SRC_DT` to the busiest US capture day and `DST_DT` to today. Naming convention going
forward: this Asia dataset is the **"dev"** slice; each event gets its own show+year.

### Verify the shift (don't trust it blind)
```sql
-- ts and ts_datetime must agree to the second
SELECT ts_datetime, date_format(from_unixtime(ts),'%Y-%m-%d %H:%i:%s') AS ts_fmt
FROM conn WHERE dt='<DST_DT>' ORDER BY ts LIMIT 3;
-- window is clean and contiguous
SELECT MIN(ts_datetime), MAX(ts_datetime), COUNT(*) FROM conn WHERE dt='<DST_DT>';
-- views lit up
SELECT alert_type, COUNT(*) FROM alerts WHERE dt='<DST_DT>' GROUP BY 1;
```
> Gotcha: don't `SELECT from_unixtime(ts)` alone in Athena output — it serializes a
> `timestamp(3)` and errors. Wrap in `date_format(...)` to return a string.

---

## Smoke-testing the app's query surface (from the host)

The SG blocks you unless you're on the allow-list, but from the box itself you can hit
nginx on localhost with a `Host:` header. Use this after seeding data or a redeploy.

```bash
ssh ubuntu@<IP>      # or aing.bhnoc.com
H='-H Host:aing.bhnoc.com -H Content-Type:application/json'

# Health + alert feed (what the dashboard polls)
curl -sk https://127.0.0.1/health $H
curl -sk https://127.0.0.1/api/v1/alerts/status $H       # {queueLength, emitted, ...}
curl -sk https://127.0.0.1/api/v1/alerts/recent $H        # last-24h alerts, newest first
```

**Real routes** (not the guessable ones): `POST /api/v1/chat`, `GET /api/v1/chat/:id`,
`GET /api/v1/alerts/recent`, `GET /api/v1/alerts/status`, `GET /health`, `GET /ws`.
There is **no** `/api/v1/alerts` (404).

The chat API is **async — poll, don't block**. Body field is **`query`** (not `message`):
```bash
JID=$(curl -sk $H -X POST https://127.0.0.1/api/v1/chat \
        -d '{"query":"How many alerts in the last 24 hours by severity?"}' \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['jobId'])")
# poll until status == done|error
curl -sk $H https://127.0.0.1/api/v1/chat/$JID | python3 -m json.tool
```
Response carries `status`, `answer` (markdown), `agentUsed`, `confidence`, `data`.

Good default queries to confirm the pipeline end-to-end:
| Query | Routes to | Confirms |
|-------|-----------|----------|
| "How many alerts in the last 24 hours by severity?" | `alert-triage` | alerts view + date window |
| "Top 5 source IPs by connection count in the last 24 hours?" | `athena-hunter` | conn NL→SQL on today's dt |
| "Show DNS queries to suspicious domains today" | `threat-hunter` | dns table |

**Known non-issue:** answers cap at `ALERT_MAX_FETCH` (200) alerts even when the raw table
has more — that's the app config, not missing data.

---

## Changing the Gemini model

Defaults to Gemini. As of 2026-07-22 the model is **`gemini-3.5-flash-lite`** (migrated from
the retired `gemini-3.1-flash-lite-preview`). Verify a model exists before using it — don't
trust memory:
```bash
KEY=<gemini key from .env.s3 / container env>
curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=$KEY" \
  | python3 -c "import sys,json;[print(m['name'].split('/')[-1]) for m in json.load(sys.stdin)['models'] if 'flash-lite' in m['name']]"
```

### ⚠️ The `thinkingBudget=0` trap
`gemini-3.5-flash-lite` **rejects `thinkingBudget=0`** with `400 INVALID_ARGUMENT` — it
cannot fully disable thinking the way the 3.1 preview could. NOCgentic's 7 fast-path call
sites pass `thinking_budget=0`. Fix (already in `agents/shared/llm_client.py`
`_get_gemini_model`): clamp `0 → -1` (dynamic) for the flash-lite family, so callers keep
expressing "don't think much" as 0. At the real budgets (256/1024 tokens) dynamic thinking
spends ~0 thinking tokens on classification prompts, so behavior matches. **Symptom if you
hit this:** orchestrator 500 → downstream agent 500 → `ChatGoogleGenerativeAIError
(INVALID_ARGUMENT)` in that agent's logs.

### Where the model is pinned
`docker-compose.agents.yml` (5× `GEMINI_MODEL` defaults), `.env.s3` (`GEMINI_MODEL=` —
authoritative, overrides compose), `agents/shared/llm_client.py` (cost map + a separate
`gemini-3.1-pro-preview` fallback used only if env unset), `agents/alert-triage/main.py`
(2 hardcoded strings). Change via `.env.s3` for a quick swap; edit code + push to `main`
for a permanent one (the remote runner deploys from main).

### Testing an LLM change locally (faithful, no container rebuild)
Match the container's `langchain-google-genai` version, then exercise the REAL module:
```bash
V=$(ssh ubuntu@<IP> 'sudo docker exec app-athena-hunter-1 python -c "import langchain_google_genai as m;print(m.__version__)"')
python3 -m venv /tmp/t && /tmp/t/bin/pip install "langchain-google-genai==$V" langchain-core
# then import agents/shared/llm_client.py and call llm_complete(..., thinking_budget=0)
```
