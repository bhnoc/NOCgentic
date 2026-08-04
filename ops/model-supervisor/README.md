# Model supervisor

A small host-side service that starts and stops the local `llama-server` units, so
the settings gear in the audit monitor can change which model a lane uses without a
redeploy.

## Why it is not in a container

The orchestrator serves the settings gear, and it runs in Docker. Letting a container
start host processes means mounting the docker socket, sharing the host PID namespace,
or handing it an SSH key. All three end the same way: the container that ships
conference traffic to an external LLM can run arbitrary commands as root on the box.

So the capability lives on the host, in one file, with three verbs. The only free
parameter any caller controls is a key into the allowlist in `supervisor.py`. No
paths, ports, flags or command strings cross the boundary. A fully compromised
orchestrator can start and stop models somebody already vetted; it cannot execute
anything else.

Hold that line if you extend it. The caller names an intent, this file decides the
command. Once a request string reaches a subprocess argument it is a remote shell.

## Install

Runs as its own user with exactly one sudoers entry. Not root.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin bhnoc-models
sudo install -d -o bhnoc-models -g bhnoc-models /opt/nocgentic/model-supervisor
sudo install -o bhnoc-models -g bhnoc-models \
  ops/model-supervisor/supervisor.py /opt/nocgentic/model-supervisor/
sudo -u bhnoc-models python3 -m venv /opt/nocgentic/model-supervisor/.venv
sudo -u bhnoc-models /opt/nocgentic/model-supervisor/.venv/bin/pip install \
  fastapi uvicorn pydantic
```

The sudoers entry, via `visudo -f /etc/sudoers.d/bhnoc-models`. Narrow on purpose:
the unit names are literal, so this grants control of these two services and nothing
else.

```
bhnoc-models ALL=(root) NOPASSWD: /usr/bin/systemctl start aqlight.service, \
  /usr/bin/systemctl stop aqlight.service, \
  /usr/bin/systemctl is-active --quiet aqlight.service, \
  /usr/bin/systemctl start foundation-sec.service, \
  /usr/bin/systemctl stop foundation-sec.service, \
  /usr/bin/systemctl is-active --quiet foundation-sec.service
```

Generate the token and keep it out of git. It is separate from
`ADMIN_BEARER_TOKEN` on purpose: this one authorises process control on the host, and
should not be the same string a browser session's admin calls carry around.

```bash
openssl rand -hex 32 | sudo tee /etc/nocgentic/model-supervisor.token
sudo chmod 600 /etc/nocgentic/model-supervisor.token
sudo chown bhnoc-models /etc/nocgentic/model-supervisor.token
```

`/etc/systemd/system/bhnoc-model-supervisor.service`:

```ini
[Unit]
Description=NOCgentic model supervisor
After=network.target

[Service]
User=bhnoc-models
EnvironmentFile=/etc/nocgentic/model-supervisor.env
ExecStart=/opt/nocgentic/model-supervisor/.venv/bin/python \
  /opt/nocgentic/model-supervisor/supervisor.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

`/etc/nocgentic/model-supervisor.env` (mode 600):

```
MODEL_SUPERVISOR_TOKEN=<the hex from above>
MODEL_SUPERVISOR_HOST=172.17.0.1
MODEL_SUPERVISOR_PORT=8790
```

`MODEL_SUPERVISOR_HOST` is the docker bridge address so containers can reach it and
nothing off-box can. The process refuses to start on `0.0.0.0`, and there is no nginx
location for the port. Confirm after starting:

```bash
sudo systemctl enable --now bhnoc-model-supervisor
ss -lntp | grep 8790     # expect 172.17.0.1:8790, never 0.0.0.0:8790
```

Then point the orchestrator at it in the on-box `.env.s3`:

```
MODEL_SUPERVISOR_URL=http://172.17.0.1:8790
MODEL_SUPERVISOR_TOKEN=<the same hex>
```

Without those two the panel renders read-only: discovery still shows what each
endpoint is serving, and the start/stop controls return 501. That is the correct state
for the CPU box and for any dev machine.

## Allowlist

`MODELS` in `supervisor.py` maps a key to a systemd unit and port. The unit file holds
the GGUF path, context size and GPU layer count, so adding a model means writing a
unit on the host and adding an entry here. Deliberately not something the API can do.

## API

All routes except `/healthz` need `Authorization: Bearer $MODEL_SUPERVISOR_TOKEN`.

| Route | Does |
|---|---|
| `GET /healthz` | Unauthenticated liveness. Says nothing but "up" |
| `GET /models` | Allowlist plus live `systemctl is-active` per unit |
| `POST /start` | `{"role": "prose", "model": "foundation-sec"}` |
| `POST /stop` | `{"role": "prose"}`, stops every active allowlisted unit |

Two behaviours worth knowing:

- **`/start` does not stop anything.** Two 7B models at useful context do not both fit
  in the T4's 15GB, so freeing VRAM is a separate, explicit call. An implicit stop
  would kill a model somebody's demo was mid-query on.
- **`aqlight.service` is `Restart=always`,** so systemd brings it straight back after
  a stop. Correct, because it is the durable default and the box should not end up
  with no local model, but it means stopping it is not how you free VRAM for long.
  Mask the unit if you need it gone.

## Checking it from the box

```bash
TOKEN=$(sudo cat /etc/nocgentic/model-supervisor.token)
curl -s -H "Authorization: Bearer $TOKEN" http://172.17.0.1:8790/models | jq
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"prose","model":"foundation-sec"}' \
  -H 'Content-Type: application/json' http://172.17.0.1:8790/start | jq
```

A unit being started is not the model being ready: `llama-server` takes tens of
seconds to map a GGUF into VRAM, which is why `/start` reports `loading: true` and the
UI polls `/models` rather than assuming.
