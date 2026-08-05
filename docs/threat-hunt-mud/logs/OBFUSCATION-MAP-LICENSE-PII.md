# Obfuscation map — cleartext license PII logs

Pulled from conference Corelight via `cortex xql` (`corelight_http_raw`) for
the cleartext vendor license activation thread. Shipped captures live in
`stagecast-license-pii-http.obfuscated.json` and `nodes[*].logs` on hunt
`stagecast-license-pii-http`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host from Slack/XQL | `10.44.32.40` |
| Peer floor host (same activate host) | `10.44.32.55` |
| Activation destination IP | `203.0.113.50` (RFC 5737 TEST-NET-3) |
| HTTP Host | `activate.stagecast.example` |
| Product / user-agent | StageCast Playback Console |
| Real person name / corp email | Riley Quill / `rquill@stagecast.example` |
| Company / serial | StageCast / `SC-77419` |
| Snapshot ComputerName / LocalIP | `STAGE-MAC-12` / `10.44.32.40` |
| Response marker `SAFEACTIVATIONRESPONSE…` | `STAGECASTACTIVATIONRESPONSE…` |
| Zeek connection UIDs | `Cfict0000201`… |
| Real SSID / room labels | general Wi-Fi (omit live SSID) |

Sensor fact retained: HTTP/80 cleartext license `GET` then `POST` to
`/activate.php` from a general Wi-Fi macOS client, form fields carry name /
email / serial / device snapshot, Apache vendor activation host, matching
UA, a second floor host repeats the same URI + field layout days later, no
follow-on exploit chain observed in the HTTP window. Close remains
**BH Benign** (vendor-normal licensing; hygiene note ≠ intrusion IR).

## XQL notes / gaps

- Primary query: `uri contains "activate.php" or host contains "<real host>" or post_body contains "SerialNumber"` → 17 rows; several unrelated activation vendors also matched `SerialNumber` / `activate` — **excluded** from the pack (only the alerted Host + peer on the same Host kept).
- Peer rollup: `comp count as hits` parse-failed; working form was `alter hits = 1 | comp sum(hits) as hits by id_orig_h` → alerted host **2**, peer **6** on `uri contains "activate.php"` for that Host family.
- Cortex top-level `host` field was often null; HTTP Host must be read from `_raw_log` `client_headers.Host` (or reconstructed).
- Event chronology uses `_raw_log.ts` (19:06:43 / 19:06:44), not `_time` insert time.
- Slack PCAP link and full conn/lateral negative search were **not** re-pulled; “no lateral sweep” is consistent with the Slack close write-up, not a fresh conn XQL prove-out in this pack.
- Entity-profile volume (conns / MB) comes from the Slack bot assessment, not from these HTTP rows.
