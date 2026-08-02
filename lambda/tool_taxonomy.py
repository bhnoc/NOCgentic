"""SNI-to-product taxonomies for the `ai_tools` and `security_tools` columns.

An analyst asking "what is this host running" gets two answers from one place: which
AI services it talks to, and which security products are installed on it. Both are
derived from TLS SNI alone, because that is the only signal that covers the whole
network — see the coverage note in asset_classification.py.

EVERY needle here is a REGISTRABLE-DOMAIN match, never a substring. That is not
style, it is the one bug this module exists to avoid. A `%ai%` rule matched
mail.google.com (374 hosts) because "m-ai-l" contains "ai", and the live traffic
carries real adtech on .ai TLDs: sync.programmaticx.ai (25), dns.nrich.ai (26),
sync.theagenticx.ai (17), secure.insightexpressai.com (24). asset_classification.py
already has the canonical scar here: 'cros' matched "Microsoft-CryptoAPI" and
reported ChromeOS on a Windows box. So a needle is a DOMAIN, and `_domain_pred`
expands it to `sni = 'd' OR sni LIKE '%.d'` — an unanchored needle is not
expressible.

MEASURED against dt='2026-08-02', in-scope only (10.220.% / 192.168.1%). The host
count in each comment is distinct in-scope id_orig_h for that entry on that day. A
needle marked SPECULATIVE matched ZERO hosts and ships anyway: these are real
products and an attendee can arrive with one tomorrow, but a future reader should
know which needles are load-bearing.

DELIBERATE OMISSIONS, from a reverse-discovery query over the top ~2,800 in-scope
registrable domains this taxonomy did NOT match:

    events.data.microsoft.com (678)   generic Windows telemetry, not Defender
    settings-win.data.microsoft.com   same
    smartscreen.microsoft.com (98)    ships in every Edge install, says nothing
    normandy.cdn.mozilla.net (99)     Firefox, not a security tool
    sentry.io (304)                   crash reporting in ~everything
    datadoghq.com browser-intake      RUM beacon FROM a website, not an agent
    okta.com (20)                     entity_context already owns this; see below

Athena engine v3 is Trino. `_case_expr` emits a CASE over an SNI expression the
caller supplies; it single-quote-escapes every literal, and it interpolates nothing
but the taxonomy's own constants.
"""

from __future__ import annotations

# The closed set. A security entry with a class outside this fails the structural
# test rather than inventing a column value nobody's dashboard knows how to render.
#
# ORDERED, and the order is the display precedence used by security_tools: a host
# usually matches more than _TOP_N products, so what survives the slice is decided
# here. Corporate CONTROLS lead (an analyst asking "who manages this box" wants the
# EDR and the MDM), and the researcher-signal classes trail — pentest and
# threat_intel are the host's OWN tooling, interesting but not a control.
SECURITY_CLASS_ORDER: tuple[str, ...] = (
    "edr", "mdm", "ztna", "secure_browser", "casb", "mfa", "vault",
    "vpn", "mesh_vpn", "dlp", "av", "siem_agent", "vuln_scanner",
    "patch_rmm", "dns_filter", "email_sec", "backup", "compliance",
    "threat_intel", "pentest",
)

SECURITY_CLASSES: frozenset[str] = frozenset(SECURITY_CLASS_ORDER)

# AI categories, same contract.
AI_CLASSES: frozenset[str] = frozenset({
    "assistant", "local_runner", "inference_api", "coding", "media_gen",
    "agent_platform", "productivity",
})


# One entry per product. `domains` are registrable domains OR longer suffixes where
# the shorter form would be too broad: 'manage.microsoft.com' is Intune but bare
# 'microsoft.com' is every Windows box on the floor, so the needle carries the label
# it needs. Order is precedence — the FIRST matching entry wins, so a narrower
# suffix must precede a broader one that would shadow it.
AI_TOOLS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    # Claude. The spec had only api.anthropic.com and thereby missed 3/4 of the
    # population: claude.ai alone is 175 hosts and the API domain is 199, but the
    # web app, the desktop updater and the artifact bridge are separate registrable
    # domains. Measured: api.anthropic.com 199, a-api.anthropic.com 98,
    # a-cdn.anthropic.com 29 | claude.ai 175, downloads.claude.ai 65,
    # assets.claude.ai 19, a-cdn.claude.ai 7 | bridge.claudeusercontent.com 61 |
    # claude.com 14, code.claude.com 9 | claudemcpcontent.com 5.
    ("Claude", "assistant", ("anthropic.com", "claude.ai", "claude.com",
                             "claudeusercontent.com", "claudemcpcontent.com")),
    # ChatGPT 236 + ab.chatgpt.com 98; oaistatic 48/19 and oaiusercontent 15/13/3/2
    # are the web app's own asset and sandbox domains, documented as required in
    # OpenAI's enterprise allowlist. openai.com is only 6 — the API is not what
    # attendees use, the web app is.
    ("ChatGPT", "assistant", ("chatgpt.com", "openai.com", "oaistatic.com",
                              "oaiusercontent.com", "sora.com")),
    # 369 hosts, the largest AI population here, and the number rests almost entirely
    # on appsgenaiserver-pa.clients6.google.com (223) + the googleapis form (92) —
    # Google's own "apps genai server", i.e. Gemini inside Workspace. Corroborated by
    # gemini.google.com 78 and gemini.gstatic.com 26.
    #
    # READ THE COUNT CAREFULLY. This is the one entry where presence does not prove
    # intent: a Workspace tenant with Gemini enabled has clients that reach this host
    # whether or not the human typed a prompt. It is an ENTITLEMENT signal more than a
    # usage one, unlike ollama.com where the software had to be installed.
    #
    # Anchored on the FULL host, never the registrable domain: clients6.google.com and
    # googleapis.com are shared Google infrastructure and a suffix match on either
    # would claim Gemini for most of the 1,236 hosts that touch google.com.
    ("Gemini", "assistant", ("gemini.google.com", "gemini.gstatic.com",
                             "appsgenaiserver-pa.clients6.google.com",
                             "appsgenaiserver-pa.googleapis.com",
                             "geminiweb-pa.googleapis.com",
                             "generativelanguage.googleapis.com",
                             "cloudcode-pa.googleapis.com",
                             "daily-cloudcode-pa.googleapis.com",
                             "notebooklm-pa.googleapis.com", "notebooklm.google.com",
                             "aistudio.google.com")),
    # copilot.microsoft.com 23, ms-sso.copilot.microsoft.com 8. NOT bare
    # microsoft.com and NOT m365.cloud.microsoft (54) — the latter is the Office
    # portal every licensed user loads whether or not Copilot is provisioned.
    ("Microsoft Copilot", "assistant", ("copilot.microsoft.com", "copilot.cloud.microsoft")),
    ("Grok", "assistant", ("grok.com", "x.ai")),                       # 7 + 2
    ("Perplexity", "assistant", ("perplexity.ai",)),                   # 11
    ("DuckDuckGo AI", "assistant", ("duck.ai",)),                      # 3
    ("Zhipu GLM", "assistant", ("z.ai", "chatglm.cn", "bigmodel.cn")),  # 3 + 2
    ("Kimi", "assistant", ("kimi.com", "moonshot.cn")),                # 2 + 2
    ("Venice AI", "assistant", ("venice.ai",)),                        # 2
    ("Mistral", "assistant", ("mistral.ai",)),                         # SPECULATIVE
    ("DeepSeek", "assistant", ("deepseek.com",)),                      # SPECULATIVE
    ("Meta AI", "assistant", ("meta.ai",)),                            # SPECULATIVE
    ("Poe", "assistant", ("poe.com",)),                                # SPECULATIVE
    ("Character.AI", "assistant", ("character.ai",)),                  # SPECULATIVE
    ("Copilot.fun", "assistant", ("copilot.fun",)),                    # 5

    # LOCAL MODEL RUNNERS. Operationally the most interesting category and the spec
    # had none of it: a host running Ollama is doing inference ON ITSELF, which is a
    # different risk conversation from a host using a hosted API. They are visible
    # because they pull models and check for updates.
    #
    # ollama.com 88 makes this the second-largest AI signal on the network, ahead of
    # every hosted API except Claude and ChatGPT. ollama.ai 2 is the legacy domain
    # (registry.ollama.ai still serves manifests).
    ("Ollama", "local_runner", ("ollama.com", "ollama.ai")),
    # lmstudio.ai 9, versions-prod.lmstudio.ai 6 (the update check) — 16 across
    # subdomains, matching the hand-broadened estimate.
    ("LM Studio", "local_runner", ("lmstudio.ai",)),
    ("Jan", "local_runner", ("jan.ai",)),                              # SPECULATIVE
    ("GPT4All", "local_runner", ("gpt4all.io", "nomic.ai")),            # SPECULATIVE
    ("Open WebUI", "local_runner", ("openwebui.com",)),                 # SPECULATIVE
    ("LocalAI", "local_runner", ("localai.io",)),                       # SPECULATIVE
    ("vLLM", "local_runner", ("vllm.ai",)),                             # SPECULATIVE

    # INFERENCE / AGGREGATION. openrouter.ai is 48 (36 apex + 25 on clerk., its auth
    # provider); huggingface.co 23 plus hf.co 3 and xethub.hf.co (the new LFS
    # backend). groq.com is ~32 across api. 9 / console. 9 / api.stytchb2b. 14 —
    # stytch is Groq's auth vendor but the hostname is under groq.com, so it
    # anchors cleanly and does NOT need a stytch needle.
    ("OpenRouter", "inference_api", ("openrouter.ai",)),
    ("Hugging Face", "inference_api", ("huggingface.co", "hf.co")),
    ("Groq", "inference_api", ("groq.com",)),
    ("Requesty", "inference_api", ("requesty.ai",)),                    # 1 + router. 1
    ("RunPod", "inference_api", ("runpod.io",)),                        # 1
    ("Baseten", "inference_api", ("baseten.co",)),                      # 2
    ("Nous Research", "inference_api", ("nousresearch.com",)),          # 2
    ("Together AI", "inference_api", ("together.ai", "together.xyz")),  # SPECULATIVE
    ("Fireworks AI", "inference_api", ("fireworks.ai",)),               # SPECULATIVE
    ("Replicate", "inference_api", ("replicate.com",)),                 # SPECULATIVE
    ("Cohere", "inference_api", ("cohere.com", "cohere.ai")),           # SPECULATIVE
    ("Cerebras", "inference_api", ("cerebras.ai",)),                    # SPECULATIVE
    ("Deepinfra", "inference_api", ("deepinfra.com",)),                 # SPECULATIVE
    ("Modal", "inference_api", ("modal.com",)),                         # SPECULATIVE
    ("AI21", "inference_api", ("ai21.com",)),                           # SPECULATIVE

    # AI CODING ASSISTANTS. githubcopilot.com is the big one at 66 and it splits by
    # licence tier, which is worth keeping as one label: api.individual 54,
    # proxy.individual 39, telemetry.individual 37, api.business 5, api.enterprise 3.
    # NOT github.com (442) — that is everyone browsing repos.
    ("GitHub Copilot", "coding", ("githubcopilot.com",)),
    # cursor.sh 19 is the API (api2. 19, api3. 11, agentn.global.api5. 6) and
    # cursor.com 3 the site. Both, because the editor uses both.
    ("Cursor", "coding", ("cursor.sh", "cursor.com")),
    # jetbrains.ai 10 is the AI Assistant specifically. jetbrains.com (52) is
    # DELIBERATELY EXCLUDED: it is the IDE itself downloading plugins and checking
    # licences, which is not an AI signal.
    ("JetBrains AI", "coding", ("jetbrains.ai",)),
    ("Codeium / Windsurf", "coding", ("codeium.com", "windsurf.com")),  # 4 + 3
    ("Cline", "coding", ("cline.bot",)),                                # 6 (otel.)
    ("Zed", "coding", ("zed.dev",)),                                    # 5
    ("OpenCode", "coding", ("opencode.ai",)),                           # 6
    ("Lovable", "coding", ("lovable.dev", "gpteng.co")),                # gpteng.co 2
    ("Tabnine", "coding", ("tabnine.com",)),                            # SPECULATIVE
    ("Sourcegraph Cody", "coding", ("sourcegraph.com",)),               # SPECULATIVE
    ("Continue", "coding", ("continue.dev",)),                          # SPECULATIVE
    ("Augment Code", "coding", ("augmentcode.com",)),                   # SPECULATIVE
    ("Supermaven", "coding", ("supermaven.com",)),                      # SPECULATIVE
    ("Replit", "coding", ("replit.com",)),                              # SPECULATIVE
    ("Vercel v0", "coding", ("v0.dev",)),                               # SPECULATIVE
    ("Bolt.new", "coding", ("bolt.new",)),                              # SPECULATIVE
    ("Qodo", "coding", ("qodo.ai", "codium.ai")),                       # SPECULATIVE
    ("Devin", "coding", ("devin.ai", "cognition.ai")),                  # SPECULATIVE

    # MEDIA GENERATION.
    ("Suno", "media_gen", ("suno.ai", "suno.com")),                     # 3 + cdn 2
    ("Midjourney", "media_gen", ("midjourney.com",)),                   # SPECULATIVE
    ("ElevenLabs", "media_gen", ("elevenlabs.io",)),                    # SPECULATIVE
    ("Stability AI", "media_gen", ("stability.ai",)),                   # SPECULATIVE
    ("Runway", "media_gen", ("runwayml.com",)),                         # SPECULATIVE
    ("Luma", "media_gen", ("lumalabs.ai",)),                            # SPECULATIVE
    ("Ideogram", "media_gen", ("ideogram.ai",)),                        # SPECULATIVE
    ("Leonardo", "media_gen", ("leonardo.ai",)),                        # SPECULATIVE
    ("HeyGen", "media_gen", ("heygen.com",)),                           # SPECULATIVE
    ("Synthesia", "media_gen", ("synthesia.io",)),                      # SPECULATIVE
    ("Civitai", "media_gen", ("civitai.com",)),                         # SPECULATIVE
    ("Black Forest Labs", "media_gen", ("bfl.ai",)),                    # SPECULATIVE
    ("Udio", "media_gen", ("udio.com",)),                               # SPECULATIVE

    # AGENT / LLMOPS PLATFORMS.
    # LangSmith MUST precede LangChain: langchain.com suffix-matches
    # smith.langchain.com, so the reverse order makes this entry dead code. The
    # shadowing gate in the tests is what caught it.
    ("LangSmith", "agent_platform", ("smith.langchain.com",)),         # SPECULATIVE
    ("LangChain", "agent_platform", ("langchain.com",)),                # docs. 3
    ("Model Context Protocol", "agent_platform", ("modelcontextprotocol.io",)),  # 2
    ("n8n", "agent_platform", ("n8n.io",)),                            # 2
    ("PromptWatch", "agent_platform", ("promptwatch.com",)),           # 1 + ingest. 1
    ("Prompt Security", "agent_platform", ("prompt.security",)),       # 1
    # 7, not speculative: cloud.langfuse.com 5 + ph. 6 + us.cloud. 3 + static. 3.
    # Someone on this floor is running LLM tracing against a hosted Langfuse.
    ("Langfuse", "agent_platform", ("langfuse.com",)),
    ("Helicone", "agent_platform", ("helicone.ai",)),                  # SPECULATIVE
    ("Braintrust", "agent_platform", ("braintrust.dev",)),             # SPECULATIVE
    ("Portkey", "agent_platform", ("portkey.ai",)),                    # SPECULATIVE
    ("Pinecone", "agent_platform", ("pinecone.io",)),                  # SPECULATIVE
    ("Weaviate", "agent_platform", ("weaviate.io",)),                  # SPECULATIVE
    ("Qdrant", "agent_platform", ("qdrant.tech",)),                    # SPECULATIVE
    ("CrewAI", "agent_platform", ("crewai.com",)),                     # SPECULATIVE
    ("Dify", "agent_platform", ("dify.ai",)),                          # SPECULATIVE
    ("Flowise", "agent_platform", ("flowiseai.com",)),                 # SPECULATIVE

    # AI-ASSISTED PRODUCTIVITY. Grammarly is the sleeper at ~53: gnar. 48,
    # gateway. 45, auth. 44, capi. 42 on grammarly.com plus the femetrics/f-log
    # telemetry hosts on grammarly.io — the .io is the EXTENSION's telemetry, so
    # both TLDs are needed to see it.
    ("Grammarly", "productivity", ("grammarly.com", "grammarly.io", "grammarly.net")),
    ("Notion AI", "productivity", ("notion.com", "notion.so")),        # 26 + 13
    ("DeepL", "productivity", ("deepl.com",)),                         # 13
    ("Otter.ai", "productivity", ("otter.ai", "aisense.com")),         # 2 + ws. 2
    ("Gamma", "productivity", ("gamma.app",)),                         # 2
    ("Wispr Flow", "productivity", ("wisprflow.ai",)),                 # api. 5
    ("QuillBot", "productivity", ("quillbot.com",)),                   # 2
    ("Granola", "productivity", ("granola.ai",)),                      # 8
    ("Krisp", "productivity", ("krisp.ai",)),                          # 8
    ("Plaud", "productivity", ("plaud.ai",)),                          # api. 2
    ("Soniox", "productivity", ("soniox.com",)),                       # 2
    ("AssemblyAI", "productivity", ("assemblyai.com",)),               # streaming. 2
    ("Sierra", "productivity", ("sierra.chat",)),                      # 4
    ("Docling", "productivity", ("docling.ai",)),                      # 2
    ("Dia Browser", "productivity", ("diabrowser.engineering",)),      # 2
    ("Fireflies", "productivity", ("fireflies.ai",)),                  # SPECULATIVE
    ("Jasper", "productivity", ("jasper.ai",)),                        # SPECULATIVE
    ("Copy.ai", "productivity", ("copy.ai",)),                         # SPECULATIVE
    ("Writer", "productivity", ("writer.com",)),                       # SPECULATIVE
    ("You.com", "productivity", ("you.com",)),                         # SPECULATIVE
    ("Phind", "productivity", ("phind.com",)),                         # SPECULATIVE
    # 8, and the tenant labels are themselves attribution: specterops-be.glean.com
    # 3 and paloaltonetworks-be.glean.com 3 alongside app.glean.com 4.
    ("Glean", "productivity", ("glean.com",)),
    ("Julius", "productivity", ("julius.ai",)),                        # SPECULATIVE
)


# Security products, same shape plus a class. Precedence matters more here: several
# vendors sell across classes, and the FIRST match wins, so the agent/telemetry
# domain must precede any broader corporate domain of the same vendor.
#
# THE MARKETING-SITE PROBLEM, specific to this network. At Black Hat, thousands of
# people BROWSE vendor websites. www.crowdstrike.com proves nothing about the host;
# ts01-b.cloudsink.net proves the Falcon sensor is running. Where the two are
# separable this table takes the TELEMETRY domain and drops the marketing one, and
# each entry says which it is. That is why crowdstrike.com is absent while
# cloudsink.net is present, and why offsec.com (44 hosts) is included but flagged.
SECURITY_TOOLS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    # EDR / XDR --------------------------------------------------------------
    # Falcon sensor telemetry. cloudsink.net is CrowdStrike's dedicated sensor
    # cloud and appears in their proxy-allowlist doc; nothing else lives there.
    # ts01-gyr-maverick 9, ts01-b 7, ts01-laggar-gcw 5 = 22 hosts. crowdstrike.com
    # (6) is EXCLUDED as marketing/console browsing.
    ("CrowdStrike Falcon", "edr", ("cloudsink.net",)),
    # dv-us-prod 6, usea1-021 4, dv-ap-southeast-1-prod 3, ioc-gw-prod-us-1b 3 =
    # 19 on sentinelone.net, the agent's console/ingest domain. sentinelone.com
    # (go./www., 2) is the marketing site and is excluded.
    ("SentinelOne", "edr", ("sentinelone.net",)),
    # Cisco Secure Endpoint (formerly AMP4E). cloud-ios-asn.amp.cisco.com 84 +
    # eu variant 7, clam-defs 6, orbital 6, visibility 4, intake 3. 84 hosts makes
    # this one of the biggest EDR populations here and NEITHER the spec nor the hand
    # list had it. Anchored on amp.cisco.com, NOT cisco.com — bare cisco.com is
    # Webex, Meraki, docs and the show's own network gear.
    ("Cisco Secure Endpoint", "edr", ("amp.cisco.com",)),
    # LimaCharlie. 26 hosts across iac. 5, docs. 4 and the rest of ~10 subdomains.
    # limacharlie.com (2) is the marketing domain; .io is the platform.
    ("LimaCharlie", "edr", ("limacharlie.io", "limacharlie.com")),
    # Defender for Endpoint. THE ONLY safe needles are the ATP gateway and the
    # security-endpoint ingest: winatp-gw-* 18/16/6/5/5/4, cp.wd.microsoft.com
    # 22/18/14, endpoint.security.microsoft.com 6/6/5. events.data.microsoft.com
    # (678!) and smartscreen (98) are generic Windows and would triple this count
    # with garbage.
    ("Microsoft Defender for Endpoint", "edr",
     ("wd.microsoft.com", "endpoint.security.microsoft.com", "winatp-gw-cus.microsoft.com",
      "winatp-gw-cus3.microsoft.com", "winatp-gw-eus.microsoft.com",
      "winatp-gw-eus3.microsoft.com", "winatp-gw-weu.microsoft.com",
      "winatp-gw-neu.microsoft.com", "winatp-gw-usmv.microsoft.com")),
    # feeds.elastic.co 50 (the detection-rule/artifact feed the agent polls) and
    # telemetry.elastic.co 38 are AGENT traffic. The registrable domain is NOT used:
    # www.elastic.co 20, vector.maps.elastic.co 12, cloud.elastic.co 11 and
    # tiles.maps.elastic.co 3 are a person reading docs or a Kibana map tile layer,
    # and folding them in inflated this from 58 agent hosts to a mixed number that
    # would read as an Elastic fleet twice its real size.
    ("Elastic Agent", "edr", ("feeds.elastic.co", "telemetry.elastic.co",
                              "artifacts.elastic.co", "epr.elastic.co",
                              "artifacts.security.elastic.co")),
    ("Carbon Black", "edr", ("conferdeploy.net", "carbonblack.io")),    # 3
    ("Tanium", "edr", ("cloud.tanium.com", "tanium.com")),             # 3 + 4
    ("Bitdefender", "edr", ("bitdefender.net", "bitdefender.com")),     # nimbus 9x2, push 9
    ("Trellix", "edr", ("manage.trellix.com", "trellix.com")),          # dxl-usw002 1
    ("Huntress", "edr", ("huntress.io",)),                              # agent. 1
    ("Wazuh", "edr", ("wazuh.com",)),                                   # cloud. 1
    ("Binalyze", "edr", ("binalyze.io",)),                              # cred.us. 2
    ("Trend Micro", "edr", ("trendmicro.com",)),                        # 5
    ("Cybereason", "edr", ("cybereason.net",)),                         # SPECULATIVE
    # 40 hosts, and NOT speculative: ch-bh.traps.paloaltonetworks.com 32 +
    # dc-bh. 22 + dc-panwhq. 3. The 'bh' tenant prefix says this is the SHOW's own
    # Cortex deployment. Anchored on traps.paloaltonetworks.com, not the bare
    # corporate domain, which is also GlobalProtect and marketing.
    ("Cortex XDR", "edr", ("traps.paloaltonetworks.com",)),
    ("Sophos Intercept X", "edr", ("sophosxl.net", "sophosupd.com", "sophos.com")),
    ("Cylance", "edr", ("cylance.com",)),                               # SPECULATIVE
    ("Deep Instinct", "edr", ("deepinstinct.com",)),                    # SPECULATIVE
    ("Arctic Wolf", "edr", ("arcticwolf.com",)),                        # SPECULATIVE
    ("Red Canary", "edr", ("redcanary.com",)),                          # SPECULATIVE
    ("Velociraptor", "edr", ("velocidex.com",)),                        # SPECULATIVE
    ("iVerify", "edr", ("iverify.io",)),                                # 1
    ("Lookout", "edr", ("lookout-life.com",)),                          # 2
    ("Zimperium", "edr", ("zimperium.com",)),                           # cdn 3, edge 2

    # MDM / UEM --------------------------------------------------------------
    # THE INTUNE TRAP. The spec matched the bare host `manage.microsoft.com` (31
    # hosts) and thereby missed the traffic that actually matters: the MDM agent
    # talks to agents.manage.microsoft.com (44) and the MAM service to
    # mamservice.manage.microsoft.com (41), plus i. 17, agents.msua05. 12, r. 11,
    # agents.msua06. 10, agents.msua02. 9, agents.msua08. 6, pins. 6. Equality on
    # the bare host sees a third of the population. A SUFFIX match is mandatory,
    # which is exactly what `_domain_pred` gives every needle here for free.
    ("Microsoft Intune", "mdm", ("manage.microsoft.com",)),
    # bhnoc.jamfcloud.com 7 and informa.jamfcloud.com 4 are the show's OWN fleet.
    ("Jamf", "mdm", ("jamfcloud.com", "jamf.com")),
    ("Kandji", "mdm", ("kandji.io",)),                                  # web-api 8 + 4
    ("Workspace ONE", "mdm", ("awmdm.com", "vmwareidentity.com")),      # 3
    ("Mosyle", "mdm", ("mosyle.com", "mosyle.io")),                     # 2 + 2
    ("Absolute", "mdm", ("absolute.com",)),                             # cadc 2
    ("ManageEngine", "mdm", ("manageengine.com", "manageengine.in")),   # 5 + 2
    ("Miradore", "mdm", ("miradore.com",)),                             # 2
    ("Ivanti Neurons", "mdm", ("ivanti.com",)),                         # SPECULATIVE
    ("Hexnode", "mdm", ("hexnode.com",)),                               # SPECULATIVE
    ("SimpleMDM", "mdm", ("simplemdm.com",)),                           # SPECULATIVE
    ("Addigy", "mdm", ("addigy.com",)),                                 # SPECULATIVE
    ("Scalefusion", "mdm", ("scalefusion.com",)),                       # SPECULATIVE
    # Apple's DEP/enrollment endpoints. deviceenrollment.apple.com 2 and
    # iprofiles.apple.com 2 mean the device is enrolled in SOME MDM — it does not
    # name which, so the label says so. Anchored on the full host: apple.com (773)
    # is every iPhone on the floor.
    ("Apple MDM enrollment", "mdm", ("deviceenrollment.apple.com", "iprofiles.apple.com",
                                     "mdmenrollment.apple.com")),
    ("deviceTRUST", "mdm", ("devicetrust.com",)),                       # locate-europe 3

    # ZTNA / SASE / SWG ------------------------------------------------------
    # Prisma Access + GlobalProtect. gpcloudservice.com 21 (gw. 7 and 4, pangp.epm.
    # 5, fei-lc-prod-us 4) plus prismaaccess.com 11 (dem. agents/api/rum/features).
    ("Palo Alto Prisma / GlobalProtect", "ztna",
     ("gpcloudservice.com", "prismaaccess.com")),
    # zscloud.net 23 + zscalerthree.net 4 + zscaler.net 3 + zscalertwo.net 7 +
    # zdxcloud.net 2. The numbered clouds are separate registrable domains, which is
    # precisely why a single 'zscaler' substring was tempting and wrong — zdxcloud
    # does not contain the string.
    ("Zscaler", "ztna", ("zscloud.net", "zscaler.net", "zscalerone.net",
                         "zscalertwo.net", "zscalerthree.net", "zscalerbeta.net",
                         "zscalergov.net", "zdxcloud.net", "zscaler.com")),
    # Cisco Secure Access / Umbrella. sse.cisco.com carries the tunnel
    # (proxy-8236318.zpc. 9, api. 5) and umbrella.com the resolver config
    # (disthost. 5, dns. 3, doh. 3). doh.opendns.com is 635 hosts and is EXCLUDED
    # entirely — that is the show's own recursive DNS, not an installed agent, and
    # including it would make 646 hosts look like Umbrella customers.
    ("Cisco Secure Access", "ztna", ("sse.cisco.com", "umbrella.com")),
    ("Netskope", "ztna", ("goskope.com",)),                             # events 8, gslb 6
    # cloudflareclient.com is the WARP client (engage. 9, consumer-masque. 4);
    # cloudflareaccess.com 4 is a tenant's Access app. cloudflare.com (502) is
    # excluded — that is half the internet's CDN.
    ("Cloudflare Zero Trust", "ztna", ("cloudflareclient.com", "cloudflareaccess.com")),
    ("Island Browser", "secure_browser", ("island.io",)),               # api. 5, 6 total
    ("Talon / Prisma Browser", "secure_browser", ("talon-sec.com",)),   # gateway.us.gs 7
    ("Twingate", "ztna", ("twingate.com",)),                            # 4
    ("Cato Networks", "ztna", ("catonetworks.com", "catonet.works")),   # 2 + 3
    ("Netbird", "mesh_vpn", ("netbird.io",)),                           # 5
    ("Fortinet FortiClient", "ztna", ("forticlient.com", "fortinet.com")),  # 2
    ("Defender for Cloud Apps", "casb", ("mcas.ms",)),                  # access. 2
    ("Perimeter 81", "ztna", ("perimeter81.com",)),                     # SPECULATIVE
    ("Menlo Security", "secure_browser", ("menlosecurity.com",)),       # SPECULATIVE
    ("iBoss", "ztna", ("iboss.com", "ibosscloud.com")),                 # SPECULATIVE
    ("Forcepoint", "ztna", ("forcepoint.com",)),                        # SPECULATIVE
    ("Appgate", "ztna", ("appgate.com",)),                              # SPECULATIVE

    # MFA / identity ---------------------------------------------------------
    # duosecurity.com 46, dominated by <tenant>.sso.duosecurity.com. NOTE THE
    # OVERLAP: entity_context._ORG_SNI already derives org_tenant from this same
    # family, so a host here is counted once as an employer signal and once as a
    # security tool. That is intended — they answer different questions — but the two
    # columns are NOT independent evidence and must not be summed as such.
    ("Duo", "mfa", ("duosecurity.com",)),
    # OKTA IS DELIBERATELY EXCLUDED. okta.com (20) / oktapreview.com (2) /
    # oktacdn.com (5) are the SSO front door for hundreds of tenants and
    # entity_context already claims them for org attribution. Labelling them a
    # security tool would double-count the same 20 hosts under a second heading and
    # tell an analyst nothing they cannot read off org_tenant.
    ("JumpCloud", "mfa", ("jumpcloud.com",)),                           # 4
    ("Yubico", "mfa", ("yubico.com",)),                                 # SPECULATIVE
    ("Silverfort", "mfa", ("silverfort.com",)),                         # SPECULATIVE
    ("HYPR", "mfa", ("hypr.com",)),                                     # SPECULATIVE
    ("Beyond Identity", "mfa", ("beyondidentity.com",)),                # SPECULATIVE

    # PASSWORD VAULTS --------------------------------------------------------
    # 1Password is the largest vault population at 81: my. 49, b5n. 49, c. 7 and a
    # long tail of <company>.1password.com (specterops 7, corelight 5, dropzone 5,
    # compunetinc 3, notsosecure 1) — those tenant labels are themselves an employer
    # signal. Plus 1passwordservices.com 24 and 1passwordusercontent.com 4.
    ("1Password", "vault", ("1password.com", "1password.eu",
                            "1passwordservices.com", "1passwordusercontent.com")),
    # 42 on bitwarden.com (notifications. 39, identity. 35) + icons.bitwarden.net 9.
    # The spec had no vault class at all; this is 39 hosts it could not see.
    ("Bitwarden", "vault", ("bitwarden.com", "bitwarden.net", "bitwarden.eu")),
    # pollserver.lastpass.com 31 is the extension's poll loop — pure agent traffic.
    ("LastPass", "vault", ("lastpass.com", "lmiapi.lastpass.com")),
    ("Dashlane", "vault", ("dashlane.com",)),                           # api. 8, ws1. 5
    ("NordPass", "vault", ("nordpass.com",)),                           # nc-mqtt 8
    ("Keeper", "vault", ("keepersecurity.com",)),                       # 4
    ("CyberArk", "vault", ("cyberark.com", "cyberark.cloud")),          # 3 + 2
    # proton.me 63 spans several products; the vault-specific host is pass-api. (2)
    # and lumo./drive-api./calendar. are not security tools. Kept as one Proton
    # entry under vault because pass is the security-relevant one, and flagged so a
    # reader knows the count is not all vault users.
    ("Proton Pass", "vault", ("pass-api.proton.me",)),
    ("Passbolt", "vault", ("passbolt.com",)),                           # SPECULATIVE
    ("Enpass", "vault", ("enpass.io",)),                                # SPECULATIVE
    ("RoboForm", "vault", ("roboform.com",)),                           # SPECULATIVE
    ("HashiCorp Vault", "vault", ("hashicorp.cloud",)),                 # SPECULATIVE

    # VPN --------------------------------------------------------------------
    # download.wireguard.com 30. This is the INSTALLER/update check, not the tunnel:
    # a WireGuard tunnel is UDP to an arbitrary peer and emits no SNI at all, so the
    # only thing SNI can ever see is the client fetching a build. Worth having —
    # it still means the software is on the box — but it undercounts by design.
    ("WireGuard", "vpn", ("wireguard.com",)),
    # api.nordvpn.com 9 + nc-mqtt.nordvpn.com 7 = 25 across nordvpn.com. Same
    # caveat: the tunnel itself is invisible, the control plane is not.
    ("NordVPN", "vpn", ("nordvpn.com", "nordvpn.net")),
    ("Proton VPN", "vpn", ("protonvpn.com", "protonvpn.net", "vpn-api.proton.me")),  # 21
    ("Private Internet Access", "vpn", ("privateinternetaccess.com", "piaservers.net",
                                        "piaproxy.net")),               # 8 + 6
    ("CyberGhost", "vpn", ("cyberghostvpn.com",)),                      # 9
    ("Surfshark", "vpn", ("surfshark.com", "surfsharkstatus.com")),      # 8 + 3
    ("Mullvad", "vpn", ("mullvad.net",)),                               # 7
    ("ExpressVPN", "vpn", ("expressvpn.com", "expressvpn.works")),       # 2 + 2
    ("IVPN", "vpn", ("ivpn.net",)),                                     # api. 2
    ("WLVPN", "vpn", ("wlvpn.com",)),                                   # api. 2
    ("PureVPN", "vpn", ("purevpn.com",)),                               # api.proxy 1
    ("Pritunl", "vpn", ("pritunl.com",)),                               # app. 5
    ("OpenVPN", "vpn", ("openvpn.net",)),                               # SPECULATIVE
    ("Windscribe", "vpn", ("windscribe.com",)),                         # SPECULATIVE
    ("TunnelBear", "vpn", ("tunnelbear.com",)),                         # SPECULATIVE
    ("IPVanish", "vpn", ("ipvanish.com",)),                             # SPECULATIVE
    ("Hotspot Shield", "vpn", ("hotspotshield.com",)),                  # SPECULATIVE

    # MESH VPN ---------------------------------------------------------------
    # Tailscale is the single biggest security-tool population the spec missed: 82
    # hosts. The bulk is the DERP relay mesh (derp3f/derp11f/derp12e/... at 6-9 hosts
    # each across ~60 relay names), plus login.tailscale.com 7 and the control plane.
    # A per-relay needle list would rot every time Tailscale adds a region, so this
    # matches the registrable domain and lets the suffix rule cover all of them.
    ("Tailscale", "mesh_vpn", ("tailscale.com",)),
    ("ZeroTier", "mesh_vpn", ("zerotier.com",)),                        # SPECULATIVE
    ("Defined Networking", "mesh_vpn", ("defined.net",)),               # SPECULATIVE
    ("Headscale", "mesh_vpn", ("headscale.net",)),                      # SPECULATIVE

    # VULN SCANNERS ----------------------------------------------------------
    # sensor.cloud.tenable.com 9 is the Nessus Agent's link-up host — agent, not a
    # human browsing. tenable.com total 10, nessus.org 10.
    ("Tenable / Nessus", "vuln_scanner", ("tenable.com", "nessus.org")),
    # endpoint.ingress.rapid7.com 4 is the Insight Agent; rapid7.com total 16.
    ("Rapid7 Insight", "vuln_scanner", ("rapid7.com",)),
    ("Qualys", "vuln_scanner", ("qualys.com",)),                        # 3
    ("Wiz", "vuln_scanner", ("wiz.io",)),                               # 2
    ("Semgrep", "vuln_scanner", ("semgrep.com", "semgrep.dev")),        # pages. 2
    ("ProjectDiscovery", "vuln_scanner", ("projectdiscovery.io",)),     # SPECULATIVE
    ("Snyk", "vuln_scanner", ("snyk.io",)),                             # SPECULATIVE
    ("Greenbone / OpenVAS", "vuln_scanner", ("greenbone.net",)),        # SPECULATIVE
    ("Orca Security", "vuln_scanner", ("orca.security",)),              # SPECULATIVE
    ("Lacework", "vuln_scanner", ("lacework.net",)),                    # SPECULATIVE

    # SIEM / LOG AGENTS ------------------------------------------------------
    # The show's OWN stack, which is why it is here at all:
    # logscale.blackhat.trycorelight.com 8 and release.api.corelight.io 3 are the NOC
    # sensors, and http-inputs-cisco-sec-bh.splunkcloud.com 3 is the Splunk HEC
    # endpoint for this event. Useful to an analyst as "this is one of ours".
    ("Corelight", "siem_agent", ("trycorelight.com", "corelight.com", "corelight.io")),
    # splunkcloud.com 31 is dominated by http-inputs-* HEC hosts, which is a
    # forwarder or a script SENDING data. telemetry-splkmobile.dataeng.splunk.com 6
    # and api.scs.splunk.com 4 are the mobile app and Splunk Cloud Services.
    ("Splunk", "siem_agent", ("splunkcloud.com", "splunk.com")),
    # DATADOG IS SPLIT ON PURPOSE. browser-intake-*.datadoghq.com (48 + 49 + 22 on
    # datadoghq-browser-agent.com + 5 eu + 2 us3) is RUM: a JavaScript beacon fired
    # by a WEBSITE THE HOST VISITED. It says nothing about the host and is EXCLUDED.
    # http-intake.logs.*.datadoghq.com (us5 82, default 5) is the Agent shipping logs
    # FROM the host, which is the real signal — so the needle is the intake host, not
    # the registrable domain. Getting this wrong would have added ~120 phantom hosts.
    ("Datadog Agent", "siem_agent", ("http-intake.logs.datadoghq.com",
                                     "http-intake.logs.us3.datadoghq.com",
                                     "http-intake.logs.us5.datadoghq.com",
                                     "http-intake.logs.datadoghq.eu",
                                     "agent-intake.logs.datadoghq.com",
                                     "agent-http-intake.logs.datadoghq.com")),
    # Same distinction: insights-collector 5 and mobile-collector 5 are agent
    # uploads. js-cdn.dynatrace.com 5 is a RUM script tag and is excluded, so
    # Dynatrace is intentionally absent from this table.
    ("New Relic", "siem_agent", ("insights-collector.newrelic.com",
                                 "mobile-collector.newrelic.com",
                                 "metric-api.newrelic.com",
                                 "log-api.newrelic.com")),
    ("Grafana", "siem_agent", ("grafana.net",)),                        # SPECULATIVE
    ("Sumo Logic", "siem_agent", ("sumologic.com",)),                    # SPECULATIVE
    ("Cribl", "siem_agent", ("cribl.cloud",)),                           # SPECULATIVE
    ("Panther", "siem_agent", ("runpanther.io",)),                       # SPECULATIVE
    ("osquery / Fleet", "siem_agent", ("osquery.io", "fleetdm.com")),    # 2 + 3
    ("Stealthwatch Cloud", "siem_agent", ("obsrvbl.com",)),              # sensor.ext 1

    # AV ---------------------------------------------------------------------
    # McAfee 53: sadownload. 40 (the DAT/engine updater), analytics.apis. 32,
    # apis. 6, nexs. 3, consumerapps. 3. That is the consumer client updating
    # itself, which is exactly what an AV signal should look like.
    ("McAfee", "av", ("mcafee.com", "mcafeedlp.com")),
    # ff.avast.com is the file-reputation service (ip-info 8, analytics 6,
    # filerep-replica-win 4) — a live lookup from the running scanner.
    ("Avast / AVG", "av", ("avast.com", "avg.com", "avcdn.net", "avgbrowser.com")),
    ("Norton", "av", ("norton.com", "nortoncdn.com", "symantec.com")),   # spocpush 5
    ("Malwarebytes", "av", ("malwarebytes.com", "threatdown.com")),      # 4 + telemetry 2
    ("ESET", "av", ("eset.com",)),                                       # 6
    ("Kaspersky", "av", ("kaspersky.com",)),                             # 3
    ("Avira", "av", ("avira.com",)),                                     # 2
    ("F-Secure / WithSecure", "av", ("f-secure.com", "withsecure.com")),  # safeavenue 2
    ("AhnLab", "av", ("ahnlab.com",)),                                   # 2
    ("ClamAV", "av", ("clamav.net",)),                                   # SPECULATIVE
    ("Webroot", "av", ("webroot.com",)),                                 # SPECULATIVE
    ("Emsisoft", "av", ("emsisoft.com",)),                               # SPECULATIVE

    # PATCH / RMM / REMOTE ACCESS --------------------------------------------
    # An RMM agent is a remote-execution channel, which is why it belongs in a
    # security column even though it is nominally IT tooling.
    ("NinjaOne", "patch_rmm", ("ninjarmm.com",)),                        # agent-app 6, 9
    ("Splashtop", "patch_rmm", ("splashtop.com",)),                      # st2-v3-dc 8, 8
    ("Automox", "patch_rmm", ("automox.com",)),                          # api/console/rtt 1
    ("Action1", "patch_rmm", ("action1.com",)),                          # server. 2
    ("TeamViewer", "patch_rmm", ("teamviewer.com",)),                     # client. 3
    ("AnyDesk", "patch_rmm", ("anydesk.com",)),                          # relay-* 2
    ("BeyondTrust", "patch_rmm", ("beyondtrustcloud.com",)),             # pm. 4
    ("Datto RMM", "patch_rmm", ("centrastage.net", "datto.com")),         # 2
    ("Chocolatey", "patch_rmm", ("chocolatey.org",)),                     # 2
    ("ConnectWise", "patch_rmm", ("screenconnect.com", "connectwise.com")),  # SPECULATIVE
    ("Kaseya", "patch_rmm", ("kaseya.net",)),                            # SPECULATIVE
    ("Atera", "patch_rmm", ("atera.com",)),                              # SPECULATIVE
    ("RustDesk", "patch_rmm", ("rustdesk.com",)),                        # SPECULATIVE
    ("N-able", "patch_rmm", ("n-able.com",)),                            # SPECULATIVE

    # DNS FILTERING ----------------------------------------------------------
    # 55 hosts: apex 33, mozilla. 16, chrome. 9. The branded subdomains are a
    # deliberate client-side secure-DNS choice, which is the signal. Kept as one
    # entry because the apex is the same DoH resolver either way.
    # doh.opendns.com (635) is EXCLUDED — see the Cisco Secure Access note.
    ("Cloudflare DNS", "dns_filter", ("cloudflare-dns.com",)),
    ("Quad9", "dns_filter", ("quad9.net",)),                             # 12
    ("Control D", "dns_filter", ("controld.com",)),                      # 2
    ("AdGuard", "dns_filter", ("adguard-dns.io", "adtidy.org", "adguard.com")),  # filters 4
    ("NextDNS", "dns_filter", ("nextdns.io",)),                          # SPECULATIVE
    ("Pi-hole", "dns_filter", ("pi-hole.net",)),                         # SPECULATIVE

    # EMAIL SECURITY / AWARENESS ---------------------------------------------
    ("Mimecast", "email_sec", ("mimecast.com",)),                        # 4
    ("Proofpoint", "email_sec", ("urldefense.com", "urldefense.proofpoint.com",
                                 "pphosted.com", "proofpoint.com")),      # 2 + 1
    ("KnowBe4", "compliance", ("knowbe4.com",)),                         # training. 1
    ("Barracuda", "email_sec", ("barracuda.com",)),                      # SPECULATIVE
    ("Abnormal", "email_sec", ("abnormalsecurity.com",)),                # SPECULATIVE
    ("Sublime Security", "email_sec", ("sublimesecurity.com",)),         # SPECULATIVE

    # DLP / INSIDER RISK -----------------------------------------------------
    # Code42 Incydr is 9 hosts and NOBODY's list had it: console.us 9, east-ocse 9,
    # domain-ingest-oauth-east.us 8, east-tps 8, east-eds 5, download-incydr 5,
    # plus a .gov tenant. That is a full agent fleet.
    ("Code42 Incydr", "dlp", ("code42.com", "crashplan.com", "crashplanpro.com")),
    ("Cyberhaven", "dlp", ("cyberhaven.io",)),                           # prod-mpg 2
    ("Varonis", "dlp", ("varonis.com",)),                                # 2
    ("Nightfall", "dlp", ("nightfall.ai",)),                             # SPECULATIVE
    ("Forcepoint DLP", "dlp", ("websense.com",)),                        # SPECULATIVE

    # BACKUP -----------------------------------------------------------------
    ("Backblaze", "backup", ("backblaze.com",)),                         # pod-* 1 each
    ("Acronis", "backup", ("acronis.com",)),                             # dl. 1
    ("Veeam", "backup", ("veeam.com",)),                                 # SPECULATIVE
    ("Rubrik", "backup", ("rubrik.com",)),                               # SPECULATIVE

    # COMPLIANCE / GRC AGENTS ------------------------------------------------
    # osquery.vanta.com 5 is the Vanta agent, not someone reading the marketing site.
    ("Vanta", "compliance", ("vanta.com",)),
    ("Drata", "compliance", ("drata.com",)),                             # SPECULATIVE
    ("Secureframe", "compliance", ("secureframe.com",)),                 # SPECULATIVE

    # THREAT INTEL LOOKUPS ---------------------------------------------------
    # A browser tab, usually, not an agent — but on this network it identifies an
    # ANALYST WORKSTATION, which is exactly the "what is this host" answer a NOC
    # wants. Labelled as its own class so nobody mistakes it for installed software.
    ("VirusTotal", "threat_intel", ("virustotal.com",)),                 # 10
    ("Shodan", "threat_intel", ("shodan.io",)),                          # 6 (wire. 3)
    ("GreyNoise", "threat_intel", ("greynoise.io",)),                    # 2
    ("AbuseIPDB", "threat_intel", ("abuseipdb.com",)),                   # 3
    ("abuse.ch", "threat_intel", ("abuse.ch",)),                         # bazaar/feodo 2
    ("Spur", "threat_intel", ("spur.us",)),                              # 2
    ("Netcraft", "threat_intel", ("netcraft.com",)),                     # mirror.toolbar 2
    ("Cisco Talos", "threat_intel", ("sourcefire.com", "threatgrid.com",
                                     "talosintelligence.com")),          # vrt/intel 1, fmc 2
    ("Wappalyzer", "threat_intel", ("wappalyzer.com",)),                 # ping. 2
    ("Bishop Fox Cosmos", "threat_intel", ("bishopfox.com",)),           # cosmos. 1
    ("Censys", "threat_intel", ("censys.io",)),                          # SPECULATIVE
    ("urlscan.io", "threat_intel", ("urlscan.io",)),                     # SPECULATIVE
    ("SecurityTrails", "threat_intel", ("securitytrails.com",)),         # SPECULATIVE
    ("Recorded Future", "threat_intel", ("recordedfuture.com",)),        # SPECULATIVE
    ("MISP", "threat_intel", ("misp-project.org",)),                     # SPECULATIVE

    # OFFENSIVE / RE TOOLING -------------------------------------------------
    # Nobody's list had this class and at BLACK HAT it is the most populous security
    # category after the EDRs. These are people's own tools, not corporate IT, which
    # makes them the strongest available signal for "this is a researcher's laptop".
    #
    # portswigger.net 28 and, critically, telemetry.portswigger.net 17 +
    # perfdata.portswigger.net 14 — Burp Suite PHONING HOME, not a website visit.
    ("Burp Suite", "pentest", ("portswigger.net", "oastify.com")),
    # offsec.com 44: www. 40, portal. 41, static. 32, api.sna. 6. Plus
    # offseclabs.com 5 (the lab VPN infrastructure) and kali.org 18. Mostly
    # course/lab access rather than an installed agent, but on this network that is
    # still "this person is running Kali or in an OffSec lab".
    ("Kali / OffSec", "pentest", ("kali.org", "kali.download", "offsec.com",
                                  "offseclabs.com", "offensive-security.com")),
    ("Hex-Rays IDA", "pentest", ("hex-rays.com",)),                      # 6 (my. 4, auth. 3)
    ("Binary Ninja", "pentest", ("binary.ninja",)),                      # master. 3, cdn 2
    ("Hashcat", "pentest", ("hashcat.net",)),                            # 3
    ("Nmap", "pentest", ("nmap.org", "insecure.org")),                    # 2
    ("Wireshark", "pentest", ("wireshark.org",)),                        # 3
    # docs.mythic-c2.net 2 — a C2 framework's documentation. At Black Hat that is a
    # training class, not an incident, but an analyst should still see it.
    ("Mythic C2", "pentest", ("mythic-c2.net",)),
    ("Hak5", "pentest", ("hak5.org",)),                                  # shop. 2
    ("Hack The Box", "pentest", ("hackthebox.com", "htb.systems")),       # 5 + 1
    ("TryHackMe", "pentest", ("tryhackme.com",)),                        # 4
    ("Root Me", "pentest", ("root-me.org",)),                            # 2 + console.pro 1
    ("RevShells", "pentest", ("revshells.com",)),                        # 3
    ("HackerTarget", "pentest", ("hackertarget.com",)),                  # 6
    ("NotSoSecure", "pentest", ("notsosecure.com",)),                    # 6
    ("RedTeam Tools", "pentest", ("redteamtools.com",)),                 # www. 4
    ("Objective-See", "pentest", ("objective-see.org",)),                # 2
    ("Flipper Zero", "pentest", ("flipperzero.one",)),                   # SPECULATIVE
    ("Tor", "pentest", ("torproject.org",)),                             # SPECULATIVE
    ("Cobalt Strike", "pentest", ("cobaltstrike.com",)),                 # SPECULATIVE
    ("Sliver", "pentest", ("sliver.sh",)),                               # SPECULATIVE
    ("Metasploit", "pentest", ("metasploit.com",)),                      # SPECULATIVE
)


def _q(literal: str) -> str:
    """A SQL string literal with embedded quotes doubled.

    No needle in this file contains an apostrophe today, but a taxonomy is the kind
    of table someone appends to at 2am during the show, and a product named
    "O'Reilly Sec" would otherwise close the literal and change the statement.
    """
    return "'" + literal.replace("'", "''") + "'"


def _domain_pred(expr: str, domain: str) -> str:
    """`expr` is exactly `domain`, or any subdomain of it. Never a substring.

    This is the entire anti-false-positive mechanism. `sni LIKE '%ai%'` matched
    mail.google.com; `sni = 'x.ai' OR sni LIKE '%.x.ai'` cannot match
    sync.programmaticx.ai because the leading dot forces a label boundary. Note that
    the '%.' form is what makes agents.manage.microsoft.com classify as Intune from a
    needle of 'manage.microsoft.com' — the spec's equality test saw a third of them.
    """
    lit = _q(domain)
    return f"({expr} = {lit} OR {expr} LIKE {_q('%.' + domain)})"


def _any_pred(expr: str, domains: tuple[str, ...]) -> str:
    return "(" + " OR ".join(_domain_pred(expr, d) for d in domains) + ")"


def _case_expr(expr: str, rules: tuple[tuple[str, str, tuple[str, ...]], ...],
               value: str = "label") -> str:
    """CASE over `expr` yielding the product label (or its class), NULL otherwise.

    Mirrors asset_classification._case_from_norm: NULL rather than a sentinel, so a
    caller can filter or COALESCE without a magic string shadowing a real match.
    Rule order is emitted verbatim, which is how precedence stays readable — the
    first WHEN that matches wins, exactly as the table is written.
    """
    if value not in ("label", "class"):
        raise ValueError(f"value must be 'label' or 'class', not {value!r}")
    whens = "\n".join(
        f"           WHEN {_any_pred(expr, domains)} THEN "
        f"{_q(label if value == 'label' else klass)}"
        for label, klass, domains in rules
    )
    return f"CASE\n{whens}\n           ELSE NULL\n         END"


def ai_tool_case(expr: str = "sni") -> str:
    """SNI -> AI product label."""
    return _case_expr(expr, AI_TOOLS, "label")


def ai_class_case(expr: str = "sni") -> str:
    """SNI -> AI category, for a consumer that wants 'local_runner' not 'Ollama'."""
    return _case_expr(expr, AI_TOOLS, "class")


def security_tool_case(expr: str = "sni") -> str:
    """SNI -> security product label."""
    return _case_expr(expr, SECURITY_TOOLS, "label")


def security_class_case(expr: str = "sni") -> str:
    """SNI -> security class, one of SECURITY_CLASSES."""
    return _case_expr(expr, SECURITY_TOOLS, "class")


def ai_any_pred(expr: str = "sni") -> str:
    """Does this SNI belong to ANY AI tool.

    Worth having separately: a WHERE that prunes to the ~1% of rows the CASE can
    label is far cheaper than evaluating the CASE over every ssl row in a partition.
    """
    return "(" + " OR ".join(
        _any_pred(expr, domains) for _, _, domains in AI_TOOLS) + ")"


def security_any_pred(expr: str = "sni") -> str:
    return "(" + " OR ".join(
        _any_pred(expr, domains) for _, _, domains in SECURITY_TOOLS) + ")"


def _sec_display(klass: str) -> str:
    """'edr' -> 'EDR', 'mesh_vpn' -> 'Mesh VPN'. The analyst-facing class prefix."""
    special = {
        "edr": "EDR", "mdm": "MDM", "ztna": "ZTNA", "mfa": "MFA", "vpn": "VPN",
        "mesh_vpn": "Mesh VPN", "av": "AV", "dlp": "DLP", "casb": "CASB",
        "siem_agent": "SIEM", "vuln_scanner": "VulnScan", "patch_rmm": "RMM",
        "dns_filter": "DNSFilter", "email_sec": "EmailSec",
        "secure_browser": "SecureBrowser", "threat_intel": "ThreatIntel",
    }
    return special.get(klass, klass.capitalize())


def ai_label_rules() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """(label, domains) for ai_tools — the bare product name, e.g. 'Ollama'."""
    return tuple((label, domains) for label, _, domains in AI_TOOLS)


def security_label_rules() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """(label, domains) for security_tools as 'EDR:CrowdStrike Falcon'.

    Emitted in SECURITY_CLASS_ORDER, not in table order: the table is grouped by
    class for readability but a host matching an EDR and a pentest tool should show
    the EDR first, and the {_TOP_N} slice downstream makes that ordering load-bearing
    rather than cosmetic.
    """
    rank = {k: i for i, k in enumerate(SECURITY_CLASS_ORDER)}
    ordered = sorted(enumerate(SECURITY_TOOLS), key=lambda e: (rank[e[1][1]], e[0]))
    return tuple(
        (f"{_sec_display(klass)}:{label}", domains)
        for _, (label, klass, domains) in ordered
    )


def classify(sni: str, rules: tuple[tuple[str, str, tuple[str, ...]], ...]) -> tuple[str, str] | None:
    """The same matching in Python, for tests and for a one-off sanity check.

    Deliberately duplicates the SQL semantics rather than parsing the generated SQL:
    a test that reimplements the matcher would pass while the SQL was wrong. This is
    the reference, and the gates assert the SQL agrees with it.
    """
    host = sni.strip().rstrip(".").lower()
    for label, klass, domains in rules:
        for domain in domains:
            if host == domain or host.endswith("." + domain):
                return label, klass
    return None


def classify_ai(sni: str) -> tuple[str, str] | None:
    return classify(sni, AI_TOOLS)


def classify_security(sni: str) -> tuple[str, str] | None:
    return classify(sni, SECURITY_TOOLS)
