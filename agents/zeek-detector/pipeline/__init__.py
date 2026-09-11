"""Zeek AI-detection pipeline, vendored from the research-pipeline repo.

Source: research-pipeline @ 0c907593f148524607be3694e1dc34b7d3271205 (APE-85 parser +
timing detector, APE-86 LangGraph classifier + findings generator). That repo has no
remote, so the modules are copied rather than pinned as a dependency.

Stages, in order:

  zeek_parser      ssl.log / conn.log (TSV or JSON)  -> normalised events, clustered
                   by (src_host, dst_host, dst_port)
  timing_detector  per-cluster sawtooth (context-reset) and agentic-loop scores
  classifier       cluster -> AI service + behaviour + confidence. Two modes over the
                   same three deterministic tools: `llm` (LangGraph ReAct agent on
                   Claude) and `rules` (the tools called directly, no network)
  findings_generator  classifications -> SOC findings with evidence chains

Changes from the research copy are confined to `classifier` and
`findings_generator` and are listed in their module docstrings.
"""

from .zeek_parser import ZeekParser
from .timing_detector import annotate_all_clusters
from .classifier import classify_all_clusters, resolve_mode
from .findings_generator import findings_to_csv, generate_findings

__all__ = [
    "ZeekParser",
    "annotate_all_clusters",
    "classify_all_clusters",
    "resolve_mode",
    "generate_findings",
    "findings_to_csv",
]
