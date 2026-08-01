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
    # Loading by path (the dir name has a hyphen, so it is not importable as a
    # package) leaves pydantic unable to resolve the `Any` in QueryResponse from
    # this module's namespace. A normal import in the container resolves fine, so
    # this is a harness artifact, not an app defect: rebuild the model explicitly.
    from typing import Any  # noqa: F401  (needed in scope for model_rebuild)
    mod.QueryResponse.model_rebuild(_types_namespace={"Any": Any, **vars(mod)})
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


class TestCoverPathsAreOneImplementation:
    """Clean-code pass: the cover response was assembled at three call sites in
    near-identical blocks, and they had already drifted. The restricted-range path
    returned the pool text raw while the other two ran sanitize_output_text. Cover
    text is author-written so nothing leaked, but a single missed sanitize on a
    deception path becomes a real leak the moment a value gets interpolated."""

    def test_all_guardrail_paths_go_through_one_helper(self, orch):
        import inspect
        src = inspect.getsource(orch)
        # Exactly one place builds a cover QueryResponse.
        assert src.count("def _serve_cover") == 1
        # And nobody assembles one by hand any more.
        assert "cover_hints = restricted_cover_hints" not in src, (
            "a call site is building the cover response inline again"
        )

    def test_cover_answer_is_always_sanitized(self, orch):
        r = orch._serve_cover("what is on 10.220.12.5", start=0.0)
        assert "10.220.12" not in r.answer
        assert "Registration" not in r.answer

    def test_every_path_returns_an_identical_shape(self, orch):
        """A path distinguishable by confidence or agent_used would fingerprint
        which guardrail fired."""
        rs = [orch._serve_cover("q", start=0.0, salt=s)
              for s in ("hints", "refused", "kill_switch")]
        assert len({r.confidence for r in rs}) == 1
        assert len({r.agent_used for r in rs}) == 1
        assert all(r.data is None for r in rs)

    def test_salt_decorrelates_hints_from_the_path(self, orch):
        """Hints must not be a reliable oracle for WHICH guardrail fired.

        With a handful of hint pools two salts do collide on some queries, and
        that is fine. An earlier version of this test asserted the hints differ
        for one specific query and failed on exactly such a collision. The real
        property is statistical: neither always-same (salt ignored) nor
        always-different (the hint pair identifies the path)."""
        total, collisions = 40, 0
        for i in range(total):
            q = f"probe query {i}"
            a = orch._serve_cover(q, start=0.0, salt="refused").hints
            b = orch._serve_cover(q, start=0.0, salt="kill_switch").hints
            if a == b:
                collisions += 1
        assert 0 < collisions < total, f"{collisions}/{total} collisions"


class TestSanitizeIsSharedNotCopied:
    """It was four byte-identical copies across the agents; the old internal-IP
    regex drifted the same way, with five copies and only one fixed."""

    def test_agents_alias_the_shared_implementation(self):
        import subprocess
        proc = subprocess.run(
            ["git", "grep", "-c", "^def sanitize(text", "--", "agents/*/main.py"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), "..", ".."),
        )
        assert not proc.stdout.strip(), (
            "an agent defines sanitize() locally again:\n" + proc.stdout
        )

    def test_shared_sanitize_scrubs_before_truncating(self):
        """Capping first would let a secret survive by sitting past the cut."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents", "shared"))
        import llm_sanitize
        padded = "x" * (llm_sanitize.MAX_LLM_CHARS - 5) + " AKIAIOSFODNN7EXAMPLE"
        out = llm_sanitize.sanitize_for_llm(padded)
        assert "AKIAIOSFODNN7EXAMPLE" not in out


class TestKnownInventoryTablesAreDocumented:
    """These tables existed in the catalog with real data, but only known_devices
    was described in SQL_GEN_PROMPT, so the model never wrote SQL against the
    others. An undocumented table is an invisible table: the data was there the
    whole time and looked missing."""

    def _prompt(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..",
                            "agents", "athena-hunter", "main.py")
        return open(path).read()

    @pytest.mark.parametrize("table", [
        "known_devices", "known_users", "known_domains", "known_names",
        "known_hosts", "known_services", "known_certs",
    ])
    def test_table_is_described_for_the_sql_generator(self, table):
        assert f"- {table}:" in self._prompt(), f"{table} is not documented"

    def test_reserved_word_column_is_called_out(self):
        """known_users.user_ has a trailing underscore because `user` is reserved.
        Without the note the model writes `SELECT user` and the query fails."""
        src = self._prompt()
        assert "user_" in src
        assert "trailing underscore" in src

    def test_username_table_is_flagged_sensitive(self):
        """Observed usernames are the strongest identity signal in the dataset."""
        assert "Treat as sensitive" in self._prompt()


class TestNewTablesAreReachableByTheApp:
    """Building a table is only half the job. Twice now a table has existed with
    real data while the app could not use it, because nothing told the SQL
    generator it was there. An undocumented table is an invisible table."""

    def _prompt(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..",
                            "agents", "athena-hunter", "main.py")
        return open(path).read()

    @pytest.mark.parametrize("table", [
        "entity_context", "kerberos", "krb5_auth", "ntlm", "net_perf",
    ])
    def test_table_is_documented(self, table):
        assert f"- {table}:" in self._prompt(), f"{table} is invisible to the model"

    def test_host_keyed_join_convention_is_explained(self):
        """entity_context and the known_* family key on ip/host_ip, NOT orig_h.
        Without this the model writes orig_h and gets COLUMN_NOT_FOUND."""
        src = self._prompt()
        assert "HOST-KEYED" in src
        assert "entity_context.ip = alerts.orig_h" in src

    def test_reserved_column_needs_quoting_is_called_out(self):
        """net_perf.window is a reserved word: unquoted it is a parse error."""
        src = self._prompt()
        assert "RESERVED WORD" in src
        assert "`window`" in src

    def test_entity_context_is_recommended_over_hand_joining(self):
        """The whole point is one join instead of six."""
        assert "instead of joining" in self._prompt()

    def test_alert_count_semantics_are_stated(self):
        """alert_count excludes ET INFO noise and alert_count_all does not. A
        consumer that mixes them up reports a DNS resolver as catastrophic."""
        src = self._prompt()
        assert "alert_count EXCLUDES" in src
        assert "alert_count_all" in src


class TestAlertTriageEnrichesByHost:
    def test_entity_lookup_exists(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..",
                            "agents", "alert-triage", "main.py")
        src = open(path).read()
        assert "async def athena_entity_context" in src
        assert "FROM entity_context WHERE ip IN" in src

    def test_host_identity_reaches_the_llm_payload(self):
        """Triage used to enrich by SESSION only, so it could say what a host did
        but never whose device it was."""
        path = os.path.join(os.path.dirname(__file__), "..", "..",
                            "agents", "alert-triage", "main.py")
        src = open(path).read()
        assert 'triage_data["host_identity"]' in src
        assert "instead of raw IPs" in src
