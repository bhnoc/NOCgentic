---
name: ops
description: Operate and maintain the running NOCgentic (bhnocgentic) Black Hat NOC platform — start/stop the EC2 instance, renew the TLS cert, restart or debug the Docker agent stack, refresh AWS credentials, manage the security-group allow-list, update DNS, seed a re-dated "demo day" of logs so the app looks live between conferences, change the Gemini model, and smoke-test the query surface. Trigger on "start/stop the NOC server", "renew the cert", "restart the agents", "the blackhat app is down", "update the allow-list", "seed demo data", "re-date the logs to today", "make the app look live", "change the gemini model", or day-2 ops on bhnocgentic.
---

# NOCgentic — Ops Skill

Day-2 operations for the Black Hat NOC platform (**bhnocgentic**, repo `bhnoc/NOCgentic`),
served at **`https://ng.bhnoc.com/`** (`ssh nocgentic`). For first-time provisioning
see [[../deploy/skill.md]].
**PostCog** (the Slack bot on the same box) is a separate app — see `blackhat/PostCog/.claude/skills/`.

Living document — append incidents, fixes, and gotchas as they happen.

## The box at a glance

| Property | Value |
|----------|-------|
| Instance ID | `i-0b278c0b3a38ebf69` (the **nocgentic box**) |
| Account / Region | `104738328073` (Product-Research) / `us-east-2` |
| Type | `g4dn.xlarge` (T4 GPU; the app itself doesn't use it) |
| App dir | `/opt/nocgentic/app` |
| Compose file | `docker-compose.agents.yml` (env file: `.env.s3`, mode 600, not in git) |
| DNS | `ng.bhnoc.com` |
| SSH | `ssh nocgentic` (see `~/.ssh/config`; 1Password agent, biometric-gated) |
| CI runner | `actions.runner.bhnoc-NOCgentic.nocgentic-box.service` at `/opt/nocgentic/actions-runner-nocgentic` |
| Athena backend | `blackhatnoc_glue`, workgroup `blackhatnoc-usa2026`, **`us-east-2`**, SAME account as the box (`104738328073`). Verified 2026-08-03 from the instance role. |

> **Host moved 2026-07-31, URL shortened 2026-08-01.** aing
> (`i-0430224b1ac82701e`, `552440750419`, `us-west-2`, `aing.bhnoc.com`) is retired: runner deregistered, and SSH to it times out from the
> current workstation. Verified on the live box 2026-08-01. Any `ssh aing` /
> `ubuntu@aing.bhnoc.com` command still below is stale — use `ssh nocgentic`. The
> old `nocgentic.bhnoc.com` URL is also gone; the app is at `ng.bhnoc.com`. The
> `sg-022b87911ecf12539` / IAM-role notes are aing's and are unverified for this box.

> **Cost discipline:** it's a GPU box the app doesn't need. **Stop it whenever it's
> idle.** Between conferences / during dev, don't leave it running overnight.

## Golden rules

1. **The public IP changes on every stop/start** (no Elastic IP). After starting, always
   re-point the box's Cloudflare A record, or SSH by raw IP.
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
# ⚠️ These are AING's values (retired box, different account). The nocgentic box is
# i-0b278c0b3a38ebf69 in account 104738328073 / us-east-2 and needs that account's
# profile, NOT VirtualPOC-*. Re-verify before running any start/stop against it.
I=i-0b278c0b3a38ebf69; R=us-east-2   # nocgentic box
# I=i-0430224b1ac82701e; R=us-west-2 # aing (retired)

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
The IP changed. Update the box's A record in the Cloudflare `bhnoc.com` zone to
the new public IP. (DNS-01 cert renewal doesn't need the record, but users and SSH-by-name do.)

---

## TLS certificate

Let's Encrypt via **certbot `dns-cloudflare`** (DNS-01). Renewal config lives at
`/etc/letsencrypt/renewal/<fqdn>.conf` (`ng.bhnoc.com.conf` on the current box);
Cloudflare token at
`/etc/letsencrypt/cloudflare.ini`. nginx mounts `/etc/letsencrypt` read-only.

### Check expiry
```bash
# on the box
sudo openssl x509 -in /etc/letsencrypt/live/current/fullchain.pem -noout -dates
```

### Renew
```bash
# on the box — DNS-01, waits ~30s for propagation. Runs long; expect a pre-delay.
sudo certbot renew --cert-name ng.bhnoc.com
# force even if not near expiry:
sudo certbot renew --cert-name ng.bhnoc.com --force-renewal
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

## Deploy a change

> **Commit identity:** this repo (and PostCog) commit as `adminofgits` via a repo-LOCAL git config (`55036044+adminofgits@users.noreply.github.com`), so GitHub attributes commits to the account that pushes them, not the global `James Pope` work identity. If commits start showing as James Pope, the local config was lost: `git config --local user.name adminofgits` + the noreply email.

**CI auto-deploy is live** (2026-07-22). Just `git push origin main` — a self-hosted
runner on the box (label `nocgentic`) picks up `.github/workflows/deploy.yml`, rsyncs the
checkout into `/opt/nocgentic/app` (preserving `.env`/`.env.s3`/`node_modules`/logs), refreshes
IMDS creds into `.env.s3`, rebuilds the compose stack, and health-checks `/health`.
Watch it: `gh run watch <id>` / `gh run list --branch main`.

> ⚠️ **Rate-limit correctness depends on the topology (QA sweep 5).** The web-server
> rate limiter keys on `X-Real-IP`, which nginx OVERWRITES with `$remote_addr` on
> every proxied request. This is only safe because web-server is `expose:`-only
> (never published to the host), so it is unreachable except through nginx. If you
> ever add a `ports:` mapping that publishes web-server (or orchestrator/agents)
> to the host, the rate limit becomes bypassable by spoofing `X-Real-IP` directly.
> Keep the agent + web-server services internal-only.
>
> ⚠️ **Two deploy gotchas (learned 2026-07-24, cost an hour):**
> 1. **`nginx/nginx-ssl.conf` edits need `--force-recreate nginx`, NOT a reload.** The
>    config is bind-mounted (`./nginx/nginx-ssl.conf:/etc/nginx/nginx.conf:ro`). rsync
>    replaces the file via write-then-rename → new inode; the running container's mount
>    still points at the OLD inode, so `nginx -s reload` re-reads stale config and silently
>    no-ops. Fix: `sudo docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d
>    --force-recreate nginx`, then confirm with `docker exec app-nginx-1 sha256sum
>    /etc/nginx/nginx.conf` == host file's sha. (Same inode-cache family as gotcha #1 in CLAUDE.md.)
> 2. **`gh run list --limit 1` can return a CACHED/older run.** When watching a specific
>    deploy, match on `headSha`: `gh run list --branch main --json databaseId,headSha
>    --jq '.[]|select(.headSha|startswith("<sha>"))|.databaseId'`. Otherwise you'll "verify"
>    against a stale run (old container uptimes) and think your deploy didn't land.

### Runner health
```bash
gh api /repos/bhnoc/NOCgentic/actions/runners --jq '.runners[]|{name,status}'   # want online
ssh nocgentic 'cd /opt/nocgentic/actions-runner-nocgentic && sudo ./svc.sh status'
#   svc.sh MUST run from the runner root: an absolute path fails with
#   "Must run from runner root or install is corrupt". cd first.
# systemd unit on the box: actions.runner.bhnoc-NOCgentic.aing-nocgentic.service (runs as ubuntu)
# NOTE: distinct from PostCog's runner (/home/ubuntu/actions-runner, label `postcog`).
```
Offline runner → deploys queue until it's back. Restart it:
`ssh nocgentic 'sudo systemctl restart actions.runner.bhnoc-NOCgentic.nocgentic-box.service'`.
Re-register (token expires): `gh api -X POST /repos/bhnoc/NOCgentic/actions/runners/registration-token --jq .token`.

### Manual fallback (runner down / off-main deploy)
From your local machine: `./scripts/deploy-agents.sh --ssh-key ~/.ssh/blackhat --ec2-ip <IP>`
(see [[../deploy/skill.md]] Path A). `ops/deploy.sh` is also safe to run by hand on the box.

---

## The Docker stack

```bash
cd /opt/nocgentic/app
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
cd /opt/nocgentic/app
sudo bash scripts/refresh-env-creds.sh .env.s3
sudo docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d
```

---

## Re-brand for the next show (EVENT_EDITION)

The public event name is one env var driving the UI tagline, the header subtitle, and all
four agent system prompts. Code composes `Black Hat {EVENT_EDITION}`
(`agents/shared/event.py`, served to the browser at `/api/v1/config`). Currently
`USA 2026`, set explicitly in `/opt/nocgentic/app/.env.s3`.

```bash
ssh nocgentic
cd /opt/nocgentic/app
cp -p .env.s3 .env.s3.bak                                        # it holds secrets; back up first
sed -i 's/^EVENT_EDITION=.*/EVENT_EDITION=Asia 2026/' .env.s3    # or "Europe 2026", "USA 2027"
docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d web-server orchestrator \
  alert-triage athena-hunter thousandeyes-analyst
curl -sk https://127.0.0.1/api/v1/config    # expect {"eventLabel":"Black Hat USA 2026"}
```

Rehearsed end to end 2026-08-01 (flipped to Asia, verified, restored to USA). Gotchas:

- **Nation + year ONLY.** The `Black Hat` prefix is added in code; including it yields
  "Black Hat Black Hat USA 2026".
- **Read compose's output, don't assume.** `Recreated`/`Started` means the new value landed;
  `Running` means compose decided nothing changed and your edit is NOT live yet. Naming the
  services does recreate them when the env genuinely differs (verified), but if you see
  `Running` across the board, add `--force-recreate`. Either way confirm with
  `docker exec app-orchestrator-1 printenv EVENT_EDITION` and the `/api/v1/config` curl.
- **Display only.** Never wire S3 prefixes, IAM names, or Athena config to it — those stay
  frozen on the `nocgentic` convention even at a USA show.
- Compose falls back to `USA 2026` if the var is missing, so a fresh box is accidentally
  right for this show and would be silently wrong for the next one.
- Never `cat .env.s3` (LLM keys + injected AWS creds). `grep '^EVENT_EDITION' .env.s3`.

## Show-day runbook (flip from dev to live at the conference)

Between events the box runs in dev posture (SG locked to a few IPs, demo data re-dated).
On show day, flip to live in this order:

1. **Instance up + DNS.** Start the instance if stopped, re-point `ng.bhnoc.com` to the new
   IP (the IP is ephemeral). See "Start / stop" above.
2. **Cert valid.** Check expiry (`certbot`/openssl below in "TLS certificate"); renew + reload
   nginx if it lapsed while the box was off. Do this BEFORE opening 443 to the audience.
3. **Creds fresh.** `refresh-env-creds.sh .env.s3` if the box was off for hours (temp creds
   expire), then recreate the stack. Confirm `/health` 200 and a chat query answers.
4. **Open 443 to the audience.** Add the audience CIDR(s) to the SG on port 443, keep SSH (22)
   restricted to operator IPs only (see allow-list below). Prod style: `--protocol tcp --port 443`,
   NOT all-protocols.
5. **Live data.** At the conference real Corelight data flows into Athena, so today's
   partition is already populated and there is nothing to seed. The old redate driver that
   used to be documented here has been deleted precisely because running it on show day
   would have deleted that partition first.
6. **Trace viewer stays operator-only.** `/bh/1337/thetraces/` keeps its nginx IP allow-list
   (operator IPs) even after 443 opens to attendees. Do not add the audience CIDR to that path.

At lockdown (event over): revoke the audience CIDR from 443, return to the dev allow-list.

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

### Current dev allow-list (2026-07-23)
Between conferences, dev-only. All protocols:
- `136.59.5.6/32` — James
- `208.93.179.62/32` — Spicer
- `136.38.201.241/32` — Spicer2 (added 2026-07-23)

(Removed at lockdown: `165.173.10.53/32` BlackHatAsia, `165.173.10.48/28`,
`86.48.10.243/32` "Spicer2", `71.229.186.132/32`. Re-add if needed.)

---

## OS patching (host security updates + kernel)

Patch the box's OS/apps periodically (116 security updates were pending at first patch,
2026-07-23). The stack survives a reboot on its own: **all 7 containers are
`unless-stopped` and both runners + `postcog` are `enabled` on boot** — so a *soft reboot*
(`systemctl reboot`, NOT stop/start) is safe and **keeps the public IP** (no DNS re-point).

Procedure (validated 2026-07-23, Ubuntu 24.04, ~10 min total):
```bash
# 0. Rollback insurance: no-reboot backup AMI (from your laptop)
AWS_PROFILE=VirtualPOC-users aws ec2 create-image --instance-id i-0430224b1ac82701e \
  --region us-west-2 --no-reboot --name "aing-prepatch-$(date +%F)" \
  --description "backup before OS patch" --query ImageId --output text

# 1. Baseline health so you can compare after (want HTTP 200)
ssh nocgentic 'curl -sk -o /dev/null -w "%{http_code}\n" https://127.0.0.1/health'

# 2. Non-interactive full upgrade — KEEP existing configs (confold), don't clobber
#    nginx/docker/ssh confs; needrestart auto-restarts services but "No containers
#    need to be restarted" (docker daemon restart doesn't bounce running containers).
ssh nocgentic '
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -qq
  sudo apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dist-upgrade
  sudo apt-get -y autoremove   # prunes old kernels'

# 3. If /var/run/reboot-required exists (kernel/apparmor/libc bump) → SOFT reboot
ssh nocgentic 'sudo systemctl reboot'
# wait ~45s, SSH comes back on the SAME IP; containers + runners auto-start.

# 4. Verify: kernel bumped, no reboot flag, 7 containers up, 3 services active, /health 200
ssh nocgentic '
  uname -r; [ -f /var/run/reboot-required ] && echo REBOOT-STILL-NEEDED || echo clean
  cd /opt/nocgentic/app && sudo docker compose -f docker-compose.agents.yml ps
  systemctl is-active actions.runner.bhnoc-NOCgentic.aing-nocgentic.service actions.runner.bhnoc-PostCog.aing-postcog.service postcog
  curl -sk -o /dev/null -w "%{http_code}\n" https://127.0.0.1/health -H "Host: ng.bhnoc.com"'
```
Then run the **query smoke tests** below — a reboot re-reads the frozen `.env.s3` creds, so
if they'd expired the agents would fail Athena (they were still valid at the 2026-07-23 patch;
refresh if needed). Delete the backup AMI + its snapshot once you're confident.

> **`--force-confold` matters:** without it, a dpkg config prompt on a live box either hangs
> the non-interactive run or silently overwrites a hand-tuned conf (nginx, sshd). Keep old.

---

## Health checks & troubleshooting

```bash
# From an allow-listed IP
curl -s -o /dev/null -w "HTTP %{http_code}\n" https://ng.bhnoc.com/health

# On the box (bypasses SG/DNS — tests the app directly)
curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://127.0.0.1/ -H 'Host: ng.bhnoc.com'
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
| athena-hunter answers "Athena syntax error / mismatched input 'LIMIT'" | Generated SQL **truncated** — on flash-lite `thinking_budget=0`→`-1` (dynamic) and thinking shares `max_output_tokens`; at 1024 the SQL got cut off mid-statement | Fixed 2026-07-23: `generate_sql` uses `max_tokens=2048`. If it recurs, bump further / check `llm.response_length` in the span |
| athena-hunter returns **0 rows** but SQL runs clean, alert-triage still finds data | Generated `dt = 'today'` as a **literal string** (partitions are `dt='YYYY-MM-DD'`), OR the demo data aged out of today's partition | Fixed 2026-07-23: token→real-date substitution in `generate_sql`. If alert-triage (today+yesterday window) has data but single-day queries don't → **re-date the slice to today** (see below) |

## Routine when bringing it back after downtime

1. Start instance; wait for `running`.
2. Re-point `ng.bhnoc.com` DNS to the new IP.
3. Check cert expiry; renew + reload nginx if lapsed.
4. `refresh-env-creds.sh .env.s3` (old creds are certainly expired).
5. `docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d`.
6. Verify `/health` from an allow-listed IP.
7. When done for the day: **stop the instance.**

---

## Athena data layout (bucket, partitions, views)

> The re-dated "demo day" seeding procedure that used to live here is GONE, along
> with `scripts/redate_slice.py`. That driver deleted the target `dt=` partition from
> Glue and S3 before every insert, and the only thing keeping it off real data was a
> hardcoded bucket name pointing at a bucket that no longer exists. A runbook that
> says "edit these constants and run it" one paragraph away from a partition delete
> is a foot-gun, and at a live show the real capture already populates today's
> partition, so there is nothing to seed. If a dev slice is ever wanted again, do it
> against a SEPARATE throwaway bucket.

The layout notes below are still accurate and worth reading before touching the lake.

### How the data is laid out (know this before touching it)
- Athena DB `blackhatnoc_glue`, workgroup `blackhatnoc-usa2026`, region **`us-east-2`**. A
  Glue call against `us-west-2` returns `EntityNotFoundException`, which reads like a
  missing table rather than a wrong region, so check the region first when that appears. The
  `athena-hunter` / `alert-triage` agents query this DB directly (containers use temp creds
  from `.env.s3`, not the app URL).
- Tables live in bucket **`blackhatnoc`**, Hive-partitioned by **`dt=YYYY-MM-DD`**
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

### Picking a window with a histogram
Useful for any windowed query, not just seeding. `conn` is ~65% of a day's bytes;
rough dial ~0.5 GB/hour.
```sql
SELECT substr(ts_datetime,1,13) AS date_hr, COUNT(*) rows
FROM conn WHERE dt='<DT>' GROUP BY 1 ORDER BY 1;
```

> Athena gotcha: do not `SELECT from_unixtime(ts)` alone. It serializes a
> `timestamp(3)` and errors. Wrap it in `date_format(...)` to get a string.

---

## Smoke-testing the app's query surface (from the host)

The SG blocks you unless you're on the allow-list, but from the box itself you can hit
nginx on localhost with a `Host:` header. Use this after seeding data or a redeploy.

```bash
ssh ubuntu@<IP>      # or ng.bhnoc.com
H='-H Host:ng.bhnoc.com -H Content-Type:application/json'

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
| "Show DNS queries to suspicious domains today" | `athena-hunter` | dns table |

**Known non-issue:** answers cap at `ALERT_MAX_FETCH` (200) alerts even when the raw table
has more — that's the app config, not missing data.

---

## AQLight local model + HYBRID provider (2026-07-30)

The box runs **hybrid** by default: `LLM_PROVIDER=gemini` + `SQLGEN_PROVIDER=local` in
`.env.s3`. Only athena-hunter's NL->SQL generation uses the local AQLight model; classify,
synthesis, and triage stay on Gemini. Eval: hybrid = 98.8% acc / 0.589 rel (full Gemini
accuracy, no AQLight hallucinations). Full detail: `docs/llm/AQLight-integration.md`.

- **AQLight is a systemd service:** `aqlight.service` (enabled, `Restart=always`, binds
  0.0.0.0:8080). `sudo systemctl status|restart aqlight`; health
  `curl -sf http://127.0.0.1:8080/health`.
- **NO fallback:** with `SQLGEN_PROVIDER=local`, if AQLight is down athena-hunter SQL gen
  ERRORS (local provider does not fall back to cloud). If athena-hunter fails on every
  query, check `systemctl status aqlight` FIRST; or unset `SQLGEN_PROVIDER` in `.env.s3`
  and recreate athena-hunter to fall back to Gemini SQL gen.
- **Bind gotcha:** llama-server must bind `0.0.0.0` (not 127.0.0.1) or the containers can't
  reach it via `host.docker.internal`. The systemd unit already does this.

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
