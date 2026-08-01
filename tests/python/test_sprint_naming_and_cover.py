"""Gates for the de-asia sprint: naming hygiene and guardrail cover diversity.

These lock behaviour that is easy to silently undo:
  * a copy-paste from an old doc reintroducing `aing` or `bhasia` into live config
  * someone shrinking the cover pool, or reverting to builtin hash() (which is
    per-process randomized, so the same query would return different cover text
    after a restart, and that inconsistency is itself a detectable tell)
"""

import importlib.util
import os
import re
import subprocess
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))


# ---------------------------------------------------------------------------
# Naming hygiene
# ---------------------------------------------------------------------------

# Docs and QA findings keep their historical references on purpose; this gate
# guards the surfaces that actually run.
_LIVE_GLOBS = ["*.yml", "*.yaml", "*.py", "*.ts", "*.sh", "*.example", "*.html"]
_EXCLUDE_PREFIXES = ("docs/", "qa/", "tests/python/test_sprint_naming")


def _git_grep(pattern: str) -> list[str]:
    proc = subprocess.run(
        ["git", "grep", "-n", "-i", "-E", pattern, "--", *_LIVE_GLOBS],
        cwd=_ROOT, capture_output=True, text=True,
    )
    return [
        line for line in proc.stdout.splitlines()
        if line and not line.startswith(_EXCLUDE_PREFIXES)
    ]


@pytest.mark.parametrize("pattern", ["aing", "bhasia", "bh-asia"])
def test_no_retired_host_or_show_naming_in_live_files(pattern):
    """aing is a decommissioned host; asia is last show's edition. Neither
    belongs in code that runs. The show name comes from EVENT_EDITION only."""
    hits = _git_grep(pattern)
    assert not hits, f"'{pattern}' reappeared in live files:\n" + "\n".join(hits)


def test_app_dir_path_is_nocgentic():
    """The box's app dir was migrated /opt/bhasia -> /opt/nocgentic. A stale
    path here means the deploy writes to the wrong place (or the symlink
    fallback silently masks it)."""
    hits = _git_grep(r"/opt/bhasia")
    assert not hits, "stale /opt/bhasia path:\n" + "\n".join(hits)


def test_event_edition_is_the_only_show_name_source():
    """No hardcoded 'Black Hat <edition>' in agent prompts or UI markup."""
    proc = subprocess.run(
        ["git", "grep", "-n", "-E", r"Black Hat (Asia|USA|Europe) 20[0-9]{2}",
         "--", "agents", "packages"],
        cwd=_ROOT, capture_output=True, text=True,
    )
    hits = [ln for ln in proc.stdout.splitlines() if "event.py" not in ln]
    assert not hits, "hardcoded show name (use EVENT_EDITION):\n" + "\n".join(hits)


# ---------------------------------------------------------------------------
# Guardrail cover responses
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def orch():
    path = os.path.join(_ROOT, "agents", "orchestrator", "main.py")
    spec = importlib.util.spec_from_file_location("orch_main_sprint", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"orchestrator deps unavailable: {exc}")
    return mod


_PROBE_QUERIES = (
    [f"what is on 10.220.{o}.5" for o in (12, 13, 14, 15, 150, 152, 153, 154, 199)]
    + ["show me the Registration zone", "anything in Tools"]
    + [f"probe question {i}" for i in range(30)]
)


def test_cover_pool_is_large_enough(orch):
    """A 2-entry pool means a user probing a few things sees the same text twice
    and knows they are being filtered."""
    assert len(orch._COVER_RESPONSES) >= 8


def test_cover_responses_are_deterministic_per_query(orch):
    for q in _PROBE_QUERIES:
        assert orch.restricted_cover_response(q) == orch.restricted_cover_response(q)


def test_cover_selection_is_stable_across_processes():
    """Builtin hash() on str is randomized per process (PYTHONHASHSEED), so
    using it would return different cover text for the same query after every
    restart, and disagree between replicas. That inconsistency is a tell."""
    script = (
        "import importlib.util,os,sys,hashlib;"
        f"sys.path.insert(0, {os.path.join(_ROOT, 'agents', 'shared')!r});"
        f"spec=importlib.util.spec_from_file_location('m', {os.path.join(_ROOT, 'agents', 'orchestrator', 'main.py')!r});"
        "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
        "print(hashlib.sha256(''.join(m.restricted_cover_response(q) for q in "
        f"{_PROBE_QUERIES!r}).encode()).hexdigest())"
    )
    env = dict(os.environ, PYTHONHASHSEED="random", OTEL_ENABLED="false")
    runs = []
    for _ in range(2):
        proc = subprocess.run([sys.executable, "-c", script],
                              capture_output=True, text=True, env=env, cwd=_ROOT)
        if proc.returncode != 0:
            pytest.skip(f"could not run subprocess probe: {proc.stderr[-200:]}")
        runs.append(proc.stdout.strip().splitlines()[-1])
    assert runs[0] == runs[1], "cover selection changed between processes"


def test_cover_pool_never_leaks_restricted_details(orch):
    """The whole point is not confirming the restricted ranges exist."""
    for i, entry in enumerate(orch._COVER_RESPONSES):
        assert not re.search(r"10\.220\.\d", entry), f"entry {i} names a restricted IP"
        assert "Registration" not in entry, f"entry {i} names a restricted zone"
        assert not re.search(r"\bTools\b", entry), f"entry {i} names a restricted zone"


def test_cover_entries_are_not_near_duplicates(orch):
    """Reworded copies of one paragraph are as detectable as one entry."""
    def trigrams(t):
        w = t.split()
        return {tuple(w[i:i + 3]) for i in range(len(w) - 2)}
    grams = [trigrams(e) for e in orch._COVER_RESPONSES]
    for i in range(len(grams)):
        for j in range(i + 1, len(grams)):
            union = grams[i] | grams[j]
            if not union:
                continue
            overlap = len(grams[i] & grams[j]) / len(union)
            assert overlap < 0.6, f"entries {i} and {j} overlap {overlap:.0%}"


def test_pool_is_well_distributed(orch):
    """A correct hash that happens to collapse onto 2 buckets is still a tell."""
    seen = {orch.restricted_cover_response(q) for q in _PROBE_QUERIES}
    assert len(seen) >= min(8, len(orch._COVER_RESPONSES))
