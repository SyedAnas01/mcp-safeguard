"""Tests for Stage 2/3 static-taint detection (taint_scanner.py).

These tests shell out to the real semgrep binary (the same engine
run_static_taint_scan uses in production) rather than mocking it -- a mocked
semgrep would only prove this module can parse whatever JSON shape the mock
returns, not that the generated rules actually catch anything. Skipped
automatically if semgrep isn't installed.
"""

import shutil
import textwrap

import pytest

from mcp_safeguard.scanner.taint_scanner import run_static_taint_scan

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def test_aliyun_shaped_command_injection_is_caught(tmp_path):
    """Reproduces the real, previously-missed aliyun/alibaba-cloud-ops-mcp-
    server shape this milestone validates against: a list-loop-registered
    handler whose parameter reaches subprocess.run(..., shell=True)."""
    _write(
        tmp_path / "local_tools.py",
        """
        import subprocess

        tools = []

        @tools.append
        def LOCAL_RunShellScript(script: str, working_directory: str = "."):
            process = subprocess.run(
                script,
                shell=True,
                cwd=working_directory,
                capture_output=True,
            )
            return process.stdout
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from . import local_tools

        for t in local_tools.tools:
            mcp.tool(t)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-CMDI" and f.tier == "S" for f in findings), findings
    cmdi = next(f for f in findings if f.rule_id == "TAINT-CMDI")
    assert cmdi.location.startswith("local_tools.py:")
    assert cmdi.taint_path is not None
    assert cmdi.taint_path[0]["kind"] == "source"
    assert cmdi.taint_path[-1]["kind"] == "sink"


def test_argv_list_form_without_shell_true_is_not_flagged(tmp_path):
    """The task's own sanitizer spec: passing an argv list with shell=False
    (the default) is not command injection -- must not fire."""
    _write(
        tmp_path / "server.py",
        """
        import subprocess

        @mcp.tool()
        def run_dot(input_file: str, output_file: str) -> dict:
            cmd = ["dot", "-Tpng", "-o", output_file, input_file]
            result = subprocess.run(cmd, capture_output=True)
            return {"ok": result.returncode == 0}
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CMDI" for f in findings), findings


def test_shell_true_with_shlex_quote_is_not_flagged(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        import subprocess
        import shlex

        @mcp.tool()
        def run_named_script(script_name: str) -> str:
            safe = shlex.quote(script_name)
            process = subprocess.run(f"./scripts/{safe}", shell=True, capture_output=True)
            return process.stdout
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CMDI" for f in findings), findings


def test_datagovuk_shaped_path_traversal_is_caught(tmp_path):
    """Reproduces the real, campaign-confirmed alphagov/datagovuk-mcp-
    prototype shape: a tool parameter is f-string-interpolated into a path
    joined onto a base dir, with no containment check, then opened."""
    _write(
        tmp_path / "server.py",
        """
        import pathlib

        @mcp.tool()
        async def get_data_manual(filename: str) -> str:
            base_dir = pathlib.Path().resolve().joinpath("content", "data-manual")
            with open(base_dir.joinpath(f"{filename}.md"), "r") as file:
                return file.read()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-PATHTRAV" and f.tier == "S" for f in findings), findings


def test_real_containment_check_clears_path_traversal(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        import os

        @mcp.tool()
        def read_file(filename: str) -> str:
            base = "/srv/data"
            real = os.path.realpath(os.path.join(base, filename))
            if os.path.commonpath([real, base]) != base:
                raise ValueError("outside base")
            with open(real) as f:
                return f.read()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-PATHTRAV" for f in findings), findings


def test_weak_startswith_sanitizer_still_flags_but_is_annotated(tmp_path):
    """Per this milestone's own spec: a bare str.startswith(base) check is
    NOT real containment and must not clear the finding -- but Stage 3
    should annotate that a (weak) check was attempted."""
    _write(
        tmp_path / "server.py",
        """
        import os

        @mcp.tool()
        def read_file(filename: str) -> str:
            base = "/srv/data"
            real = os.path.realpath(os.path.join(base, filename))
            candidate = os.path.join(base, filename)
            if not candidate.startswith(base):
                raise ValueError("outside base")
            with open(candidate) as f:
                return f.read()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    matches = [f for f in findings if f.rule_id == "TAINT-PATHTRAV"]
    assert matches, findings
    notes = " ".join(step["note"] for step in matches[0].taint_path)
    assert "weak" in notes and "startswith" in notes


def test_ssrf_sink_with_no_guard_is_caught(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        import requests

        @mcp.tool()
        def fetch_url(url: str) -> str:
            response = requests.get(url)
            return response.text
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-SSRF" and f.tier == "S" for f in findings), findings


def test_ssrf_with_guard_wrapped_at_the_sink_is_not_flagged(tmp_path):
    """Verified empirically against the real semgrep binary: a sanitizer
    pattern clears taint when it wraps the value at the point of use
    (`sink(validate(x))`) or reassigns it to a NEW name (`y = validate(x)`).
    See test_assert_style_guard_does_not_clear_taint below for the shape
    that does NOT clear it, an important, separately-documented limitation."""
    _write(
        tmp_path / "server.py",
        """
        import requests

        @mcp.tool()
        def fetch_url(url: str) -> str:
            response = requests.get(validate_url(url))
            return response.text
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-SSRF" for f in findings), findings


def test_assert_style_guard_does_not_clear_taint_known_limitation(tmp_path):
    """Documents a real, empirically-verified limitation (see
    MILESTONE_1_STATUS.md): semgrep OSS taint mode does NOT treat a bare,
    assert-style guard call -- `validate_url(url)` executed for its side
    effect/return value, with `url` itself never reassigned -- as
    sanitizing `url` for its later use, even though this is a common,
    legitimate idiom in real code. This is a genuine false-positive risk on
    code written this way, not a bug in this project's own rule generation
    -- confirmed by testing the identical shape directly against the
    semgrep binary in isolation, outside this codebase entirely."""
    _write(
        tmp_path / "server.py",
        """
        import requests

        @mcp.tool()
        def fetch_url(url: str) -> str:
            validate_url(url)
            response = requests.get(url)
            return response.text
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-SSRF" for f in findings), (
        "if this now passes, semgrep's sanitizer handling for assert-style guards has "
        "changed -- update MILESTONE_1_STATUS.md's limitations section to match"
    )


def test_no_entrypoints_returns_empty_without_running_semgrep(tmp_path):
    _write(
        tmp_path / "server.py",
        """
        def helper(x: str) -> str:
            return x
        """,
    )
    assert run_static_taint_scan(tmp_path) == []


def test_credfwd_hf_shaped_two_statement_headers_dict_is_caught(tmp_path):
    """Reproduces a constructed Python-equivalent of the real, campaign-
    confirmed huggingface/hf-mcp-server shape (GHSA-6w92-f47f-5xx8,
    round44-official-orgs-findings/01-huggingface-hf-mcp-server-gradio-space-
    token-forwarding.md): `callGradioToolWithHeaders` builds a destination
    URL from a caller-supplied tool argument and, in the SAME call, attaches
    the server's own bearer token with no destination-trust check. The real
    instance is TypeScript; this pipeline is Python-only (see
    entrypoints.py), so this is a constructed equivalent, not a claim this
    rule was run against hf-mcp-server's actual source -- see
    MILESTONE_CLASSES_STATUS.md."""
    _write(
        tmp_path / "server.py",
        """
        import os
        import requests

        API_TOKEN = os.environ["HF_TOKEN"]

        @mcp.tool()
        def invoke_space(space_name: str, params: dict) -> dict:
            mcp_url = f"https://{space_name}.hf.space/gradio_api/mcp/"
            headers = {"X-HF-Authorization": f"Bearer {API_TOKEN}"}
            response = requests.post(mcp_url, json=params, headers=headers)
            return response.json()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-CREDFWD" and f.tier == "S" for f in findings), findings
    hit = next(f for f in findings if f.rule_id == "TAINT-CREDFWD")
    assert hit.confidence == "high"
    assert hit.location.startswith("server.py:")


def test_credfwd_inline_headers_dict_is_caught(tmp_path):
    """The single-statement variant of the same shape: the credential-
    bearing headers dict is built inline in the call itself."""
    _write(
        tmp_path / "server.py",
        """
        import os
        import requests

        API_TOKEN = os.environ["HF_TOKEN"]

        @mcp.tool()
        def invoke_space(space_name: str, params: dict) -> dict:
            mcp_url = f"https://{space_name}.hf.space/gradio_api/mcp/"
            response = requests.post(mcp_url, json=params, headers={"Authorization": f"Bearer {API_TOKEN}"})
            return response.json()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_credfwd_auth_kwarg_is_caught(tmp_path):
    """requests' own `auth=` kwarg is inherently credential-bearing
    regardless of its value's shape -- no headers dict needed."""
    _write(
        tmp_path / "server.py",
        """
        import os
        import requests

        API_TOKEN = os.environ["HF_TOKEN"]

        @mcp.tool()
        def invoke_space(space_name: str, params: dict) -> dict:
            mcp_url = f"https://{space_name}.hf.space/gradio_api/mcp/"
            response = requests.post(mcp_url, json=params, auth=(API_TOKEN, ""))
            return response.json()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_credfwd_no_credential_attached_is_not_flagged(tmp_path):
    """Same tainted-destination shape as the caught case, but no credential
    is attached to the call -- the SSRF class may still fire on this (out of
    scope for this test), but CREDFWD, which requires BOTH conditions, must
    not."""
    _write(
        tmp_path / "server.py",
        """
        import requests

        @mcp.tool()
        def invoke_space(space_name: str, params: dict) -> dict:
            mcp_url = f"https://{space_name}.hf.space/gradio_api/mcp/"
            response = requests.post(mcp_url, json=params)
            return response.json()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_credfwd_credential_to_a_fixed_non_tainted_destination_is_not_flagged(tmp_path):
    """A credential attached to an outbound call is completely ordinary and
    safe when the destination is NOT reachable from a tool argument (a
    server calling its own, fixed backend with its own credential) --
    CREDFWD requires BOTH conditions, and must not fire on credential
    presence alone."""
    _write(
        tmp_path / "server.py",
        """
        import os
        import requests

        API_TOKEN = os.environ["HF_TOKEN"]

        @mcp.tool()
        def call_internal_api(payload: dict) -> dict:
            headers = {"Authorization": f"Bearer {API_TOKEN}"}
            response = requests.post("https://api.internal.example.com/v1/run", json=payload, headers=headers)
            return response.json()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_credfwd_destination_validated_before_credentialed_call_is_not_flagged(tmp_path):
    """Reassigning the destination through a host-validation call (same
    sanitizer vocabulary as TAINT-SSRF, since the real fix here is exactly a
    destination-trust gate -- see hf-mcp-server's own "Suggested fix")
    clears the taint, mirroring TAINT-SSRF's own proven reassignment-clears
    behavior."""
    _write(
        tmp_path / "server.py",
        """
        import os
        import requests

        API_TOKEN = os.environ["HF_TOKEN"]

        @mcp.tool()
        def invoke_space(space_name: str, params: dict) -> dict:
            mcp_url = f"https://{space_name}.hf.space/gradio_api/mcp/"
            mcp_url = validate_url(mcp_url)
            headers = {"X-HF-Authorization": f"Bearer {API_TOKEN}"}
            response = requests.post(mcp_url, json=params, headers=headers)
            return response.json()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_idor_ragflow_shaped_unchecked_id_is_caught(tmp_path):
    """Reproduces the real, campaign-confirmed oraichain/ragflow-mcp shape,
    already in this project's own frozen holdout (bench/holdout_frozen.yaml,
    target oraichain-ragflow-mcp) for a related finding on the same file:
    `upload_rag`'s `dataset_name` tool parameter reaches
    `ragflow.get_dataset(name=dataset_name)` with no ownership/tenant check
    anywhere in the function.

    IDOR-fix milestone update: the real ragflow-mcp repo has its own
    `auth.py` (a JWT-bearer-token SSE-transport auth layer -- see
    bench/MILESTONE_IDOR_FIX_STATUS.md) sitting right next to `main.py`,
    which is real evidence this repo actually has a caller-identity concept
    -- exactly the kind of file the Fix-1 tenancy gate's signal #2 looks
    for. Without a same-shaped file in this fixture, the gate would (by
    design) suppress this finding by default -- not because the fix
    regressed, but because a single `server.py` with nothing else in the
    directory is genuinely indistinguishable from one of the single-tenant
    false positives this milestone fixed. Reproducing that file here keeps
    this test a faithful, not just convenient, model of the real target.
    """
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def upload_rag(dataset_name: str, display_names: list, blobs: list) -> str:
            dataset = ragflow.get_dataset(name=dataset_name)
            response = dataset.upload_documents(display_names)
            return response
        """,
    )
    _write(
        tmp_path / "auth.py",
        """
        class JwtAuthTransport:
            async def connect_sse(self, scope, receive, send):
                auth_header = dict(scope["headers"]).get(b"authorization", b"")
                if not auth_header:
                    raise HTTPException(status_code=401, detail="Unauthorized")
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-IDOR" and f.tier == "S" for f in findings), findings
    hit = next(f for f in findings if f.rule_id == "TAINT-IDOR")
    assert hit.confidence == "low"
    assert "may be a false negative if the check happens elsewhere" in hit.description
    assert hit.location.startswith("server.py:")


def test_idor_bare_guard_check_present_suppresses_the_finding(tmp_path):
    """The absence-based design's core claim: semgrep's own dataflow does
    NOT clear taint for a bare assert-style guard call (the same empirical
    limitation TAINT-SSRF's own test documents), so this project's OWN
    Python code -- not semgrep -- must be what suppresses the finding once
    a recognized authorization-check call is found on the path."""
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def upload_rag(dataset_name: str, display_names: list, blobs: list) -> str:
            if not check_access(dataset_name, current_user):
                raise PermissionError("not allowed")
            dataset = ragflow.get_dataset(name=dataset_name)
            response = dataset.upload_documents(display_names)
            return response
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_inline_ownership_filter_on_the_sink_line_suppresses_the_finding(tmp_path):
    """A check embedded directly in the sink call's own arguments (a
    Django-style `.filter(id=..., owner=...)`) is never walked by
    reconstruct_path's statement-order passes (both only look strictly
    BEFORE the sink line) -- the supplementary same-line check must catch
    this instead."""
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str):
            return store.objects.filter(id=record_id, owner=current_user).first()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_bare_dict_get_is_not_flagged(tmp_path):
    """False-positive guard: a bare, unsuffixed `.get(` (dict.get(),
    os.environ.get(), request.args.get()) is the single largest realistic
    false-positive source for this class and must never match -- only an
    underscore-suffixed, resource-naming form (get_dataset, fetch_record,
    ...) or one of the explicitly-listed bare verbs does."""
    _write(
        tmp_path / "server.py",
        """
        import os

        @mcp.tool()
        def read_config(config_key: str) -> str:
            value = os.environ.get(config_key)
            return value or ""
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_same_function_name_in_a_non_entrypoint_file_is_not_cross_contaminated(tmp_path):
    """Regression test for a real false-positive class found and fixed
    during this milestone's own validation (ahujasid/blender-mcp): a
    same-named function in a file that never registers anything as an MCP
    tool must not be treated as tainted just because a DIFFERENT file's
    real entrypoint shares its name."""
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_status(user_prompt: str = "") -> str:
            return "ok"
        """,
    )
    _write(
        tmp_path / "addon.py",
        """
        class Handler:
            def get_status(self, user_prompt):
                with open(user_prompt) as f:
                    return f.read()
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any("addon.py" in f.location for f in findings), findings


# --------------------------------------------------------------------------
# IDOR-fix milestone: Fix 1 (tenancy-evidence confidence gate) and Fix 2
# (expanded auth-check vocabulary: decorators, ORM filters, Django
# shortcuts, FastAPI Depends comparisons).
# --------------------------------------------------------------------------


def _idor_shaped_single_tenant_repo(tmp_path):
    """A minimal IDOR-shaped hit with NO tenancy evidence anywhere in the
    directory -- the shape shared by all three of this milestone's
    real-corpus spot-checked false positives (an IDA Pro plugin, an
    RSS-search scoring loop, a Home Assistant add-on tool): a data-access
    call keyed by a tainted, resource-ID-shaped parameter, no check, and
    nothing in the project that looks like more than one caller/tenant."""
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str):
            return store.fetch_record(record_id)
        """,
    )


def test_idor_suppressed_by_default_when_project_has_no_tenancy_evidence(tmp_path):
    """Fix 1's core claim: a project with none of the four tenancy signals
    gets its TAINT-IDOR finding suppressed by default, not just
    downgraded-but-still-shown -- matching the real IDA Pro/RSS-search/
    Home Assistant false positives measured on the round-40 corpus."""
    _idor_shaped_single_tenant_repo(tmp_path)
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_shown_with_include_low_confidence_and_downgraded(tmp_path):
    """The suppression above is recoverable, not silent data loss:
    include_low_confidence=True (the CLI's --include-low-confidence) surfaces
    the same finding again, downgraded to confidence='very-low' with an
    explicit no-tenancy-evidence caveat in its description."""
    _idor_shaped_single_tenant_repo(tmp_path)
    findings = run_static_taint_scan(tmp_path, include_low_confidence=True)
    hits = [f for f in findings if f.rule_id == "TAINT-IDOR"]
    assert len(hits) == 1, findings
    assert hits[0].confidence == "very-low"
    assert "no evidence of multi-tenancy" in hits[0].description


def test_idor_single_global_tenant_config_value_does_not_count_as_tenancy_evidence(tmp_path):
    """Regression test for the real redis/mcp-redis false-positive shape
    found while building this gate: `tenant_id` appears throughout
    entraid_auth.py-style code, but only ever as ONE fixed Azure-AD tenant
    the whole server authenticates AS (read once from an env var, never
    compared against a caller-supplied value) -- not evidence of
    per-request multi-tenancy. Requiring id-as-PARAMETER *and* a
    comparison/filter is exactly what a single global config value fails."""
    _idor_shaped_single_tenant_repo(tmp_path)
    _write(
        tmp_path / "config.py",
        """
        import os

        ENTRAID_CFG = {
            "tenant_id": os.getenv("REDIS_ENTRAID_TENANT_ID", None),
            "client_id": os.getenv("REDIS_ENTRAID_CLIENT_ID", None),
        }

        def build_credential():
            return ENTRAID_CFG["tenant_id"]
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_not_suppressed_when_project_has_id_parameter_and_comparison(tmp_path):
    """Signal #1 (the strong one): a tenancy id used BOTH as a function
    parameter (varies per call) AND in a comparison/filter, anywhere in the
    project (not necessarily the same file as the sink) -- a real
    multi-tenant codebase's finding must survive the gate."""
    _idor_shaped_single_tenant_repo(tmp_path)
    _write(
        tmp_path / "authz.py",
        """
        def load_for(user_id: str, requested_owner_id: str):
            if user_id != requested_owner_id:
                raise PermissionError("not your resource")
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_not_suppressed_when_project_has_multi_tenant_framework_import(tmp_path):
    """Signal #3: an explicit multi-tenant/identity-provider framework
    import anywhere in the project is enough evidence on its own."""
    _idor_shaped_single_tenant_repo(tmp_path)
    _write(tmp_path / "identity.py", "from fastapi_users import FastAPIUsers\n")
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_auth_native_style_filename_is_not_treated_as_model_file(tmp_path):
    """Regression test for the real homeassistant-ai/ha-mcp false positive:
    a file named `auth_native.py` (its own single-installation OAuth
    resource-server helper) must NOT satisfy the model-file signal --
    _TENANCY_MODEL_FILE_STEMS is an EXACT basename-stem match ('auth'), not
    a substring match, specifically so a near-miss filename like this one
    doesn't get treated as evidence of the scanned project's OWN
    multi-tenancy. (ha-mcp's real user_id usage was separately confirmed,
    in this milestone's own validation, to never satisfy the comparison
    half of signal #1 either -- covered by the corpus re-run, not re-proven
    here.)"""
    _idor_shaped_single_tenant_repo(tmp_path)
    _write(
        tmp_path / "auth_native.py",
        """
        def validate_bearer_token(token):
            return token == LOCAL_SUPERVISOR_TOKEN
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_tenancy_gate_scoped_to_nearest_project_not_whole_monorepo(tmp_path):
    """Regression test for the real IBM/mcp-context-forge monorepo shape: a
    single clone containing a genuinely multi-tenant product AND a bundled,
    single-tenant demo tool with its OWN separate project marker. The outer
    repo's own auth.py must NOT leak tenancy evidence into the unrelated
    inner subproject's gate decision -- _nearest_project_root scopes the
    scan to the subproject with its own pyproject.toml, not tmp_path."""
    _write(tmp_path / "pyproject.toml", "[project]\nname = \"outer-gateway\"\n")
    _write(
        tmp_path / "auth.py",
        """
        class UserSessionStore:
            pass
        """,
    )
    subtool = tmp_path / "mcp-servers" / "python" / "mcp-rss-search"
    subtool.mkdir(parents=True)
    _write(subtool / "pyproject.toml", "[project]\nname = \"mcp-rss-search\"\n")
    _write(
        subtool / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str):
            return store.fetch_record(record_id)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_object_scoped_decorator_on_handler_suppresses_finding(tmp_path):
    """Fix 2's decorator-level check: an object/permission-scoped decorator
    on the HANDLER FUNCTION ITSELF (not a call inside its body) must be
    recognized -- reconstruct_path's statement-order walk previously never
    looked at fn.decorator_list at all. Tenancy evidence is included
    (auth.py) so this test isolates the decorator fix from the Fix-1 gate."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        @permission_required("dataset:read")
        def get_record(record_id: str):
            return store.fetch_record(record_id)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_authn_only_decorator_does_not_suppress_finding(tmp_path):
    """The other half of Fix 2's decorator work: an AUTHENTICATION-only
    decorator (@login_required) must NOT suppress the finding -- it proves
    the caller is logged in, not that they own this specific resource.
    Treating it as equivalent would turn a real authenticated-user-reads-
    another-user's-resource bug into a silent false negative."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        @login_required
        def get_record(record_id: str):
            return store.fetch_record(record_id)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_fastapi_depends_current_user_comparison_suppresses_finding(tmp_path):
    """Fix 2's FastAPI dependency-injection pattern: `current_user =
    Depends(get_current_user)` establishing an identity, then a SUBSEQUENT
    comparison against a resource's owner field -- a bare ast.Compare that
    neither of reconstruct_path's original two passes (Assign-only,
    Call-only) ever turned into a Step at all."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str, current_user = Depends(get_current_user)):
            record = store.fetch_record(record_id)
            if record.owner_id != current_user.id:
                raise PermissionError("not your resource")
            return record
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_orm_filter_by_kwarg_suppresses_finding(tmp_path):
    """Fix 2's ORM vocabulary: `.filter_by(user_id=...)` (SQLAlchemy's own
    spelling, previously not recognized -- only Django's `.filter(...)` was)
    used as a bare guard before the sink."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str):
            session.query(Record).filter_by(id=record_id, user_id=current_user.id).one()
            return store.fetch_record(record_id)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_django_get_object_or_404_with_owner_filter_suppresses_finding(tmp_path):
    """Fix 2's Django vocabulary: get_object_or_404() WITH an owner-ish
    kwarg is a real ownership check (the task's own named example)."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str):
            get_object_or_404(Record, pk=record_id, owner=request.user)
            return store.fetch_record(record_id)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_idor_bare_get_object_or_404_without_owner_filter_still_flags(tmp_path):
    """Negative control for the get_object_or_404 vocabulary above: WITHOUT
    an owner-ish kwarg, get_object_or_404() is just a lookup-or-404, not an
    ownership check -- must still flag (proves the fix didn't just whitelist
    the function name blindly)."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        @mcp.tool()
        def get_record(record_id: str):
            get_object_or_404(Record, pk=record_id)
            return store.fetch_record(record_id)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-IDOR" for f in findings), findings
# TAINT-CREDFWD, JS/TS port (see MILESTONE_CREDFWD_JS_STATUS.md). Fixtures
# below are minimal, structurally-faithful reproductions of the real,
# already-disclosed huggingface/hf-mcp-server shapes (GHSA-6w92-f47f-5xx8) --
# this class's own module comments in taint_scanner.py have the full trace
# and the real repo's exact file:line citations; these tests exist to pin
# the MECHANICS down against small fixtures a human can read in one glance,
# the same role the existing Python CREDFWD tests above already play for
# the Python rule.
# --------------------------------------------------------------------------


def test_credfwd_js_wrapper_call_invoke_ts_shaped_is_caught(tmp_path):
    """Reproduces the real hf-mcp-server bug's `invoke.ts:91` shape: a
    plain (not `server.tool()`-registered) helper function whose OWN
    `spaceName` parameter reaches a destination URL, passed alongside the
    server's own `hfToken` parameter as a bare positional argument to a
    project-specific wrapper call -- no literal fetch/axios/headers dict
    anywhere. Caught only because TAINT-CREDFWD-JS sources from ANY
    function's own parameters for this one class (see
    `_CREDFWD_JS_ANY_FUNCTION_SOURCE_YAML`'s own comment), not just a
    recovered MCP entrypoint's -- `invokeSpace` here is deliberately NOT
    wrapped in a `server.tool()` call, matching the real target exactly."""
    _write(
        tmp_path / "invoke.ts",
        """
        export async function invokeSpace(
        	spaceName: string,
        	hfToken?: string,
        ): Promise<void> {
        	const metadata = await fetchSpaceMetadata(spaceName, hfToken);
        	const mcpUrl = `https://${metadata.subdomain}.hf.space/gradio_api/mcp/`;
        	const { result } = await callGradioToolWithHeaders(mcpUrl, "tool", {}, hfToken, {});
        	return result;
        }
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-CREDFWD"]
    assert any(h.location.startswith("invoke.ts:") for h in hits), findings
    hit = next(h for h in hits if h.location.startswith("invoke.ts:"))
    assert hit.tier == "S"
    # The generic wrapper-call alternative -- lower confidence, on purpose,
    # per this class's own documented false-positive sweep result.
    assert hit.confidence == "medium"
    assert "GENERIC" in hit.description


def test_credfwd_js_ifchain_gradio_caller_shaped_is_caught(tmp_path):
    """Reproduces the real hf-mcp-server bug's OTHER real call site,
    `gradio-caller.ts:190-206`: the destination and the credential are both
    this function's OWN parameters, the credential dict is built and
    attached to a shared options object INSIDE an `if (hfToken)` block, and
    the destination is only actually dispatched several statements later,
    OUTSIDE that block, via a constructor call -- not a bare function call.
    This is the alternative that needed the if-wrapped chain pattern (see
    that pattern's own comment for why a flat, non-if-wrapped 3-statement
    pattern does not match this real shape)."""
    _write(
        tmp_path / "gradio-caller.ts",
        """
        export async function callGradioToolWithHeaders(
        	mcpUrl: string,
        	toolName: string,
        	parameters: Record<string, unknown>,
        	hfToken: string | undefined,
        ): Promise<void> {
        	const transportOptions: TransportOptions = {};
        	if (hfToken) {
        		const customHeaders = {
        			'X-HF-Authorization': `Bearer ${hfToken}`,
        		};
        		transportOptions.requestInit = {
        			headers: customHeaders,
        		};
        	}
        	const transport = new StreamableHTTPClientTransport(mcpUrl, transportOptions);
        	return transport;
        }
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-CREDFWD"]
    assert any(h.location.startswith("gradio-caller.ts:") for h in hits), findings
    hit = next(h for h in hits if h.location.startswith("gradio-caller.ts:"))
    # The if-chain alternative -- a much more specific structural match
    # (a real credential-vocabulary header dict, not just an argument
    # name) than the generic wrapper-call alternative, so this one keeps
    # the default "high" confidence.
    assert hit.confidence == "high"


def test_credfwd_js_literal_header_in_registered_handler_is_caught(tmp_path):
    """The 'common case' this class's standard per-entrypoint rule (not the
    any-function-parameter one) targets: the bug is fully contained inside
    one recognized `server.tool()` handler's own function, via a literal
    fetch()+headers dict -- no wrapper function involved at all."""
    _write(
        tmp_path / "server.ts",
        """
        server.tool('invoke_space', { spaceName: z.string() }, async ({ spaceName }) => {
        	const apiToken = process.env.HF_TOKEN;
        	const url = `https://${spaceName}.hf.space/api`;
        	const headers = { 'X-HF-Authorization': `Bearer ${apiToken}` };
        	const res = await fetch(url, { headers: headers });
        	return { content: [{ type: 'text', text: await res.text() }] };
        });
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-CREDFWD"]
    assert any(h.location.startswith("server.ts:") for h in hits), findings
    assert next(h for h in hits if h.location.startswith("server.ts:")).confidence == "high"


def test_credfwd_js_wrapper_no_credential_attached_is_not_flagged(tmp_path):
    """Same tainted-destination wrapper-call shape as the caught case, but
    the second argument isn't credential-shaped by name -- CREDFWD, which
    requires BOTH conditions, must not fire."""
    _write(
        tmp_path / "invoke.ts",
        """
        export async function invokeSpace(spaceName: string, requestId: string): Promise<void> {
        	const mcpUrl = `https://${spaceName}.hf.space/gradio_api/mcp/`;
        	await callGradioToolWithHeaders(mcpUrl, "tool", {}, requestId, {});
        }
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_credfwd_js_wrapper_destination_validated_is_not_flagged(tmp_path):
    """Reassigning the destination through a host-validation call (same
    sanitizer vocabulary as TAINT-SSRF-JS) clears the taint before the
    wrapper call, mirroring the Python rule's own proven
    reassignment-clears behavior."""
    _write(
        tmp_path / "invoke.ts",
        """
        export async function invokeSpace(spaceName: string, hfToken: string): Promise<void> {
        	let mcpUrl = `https://${spaceName}.hf.space/gradio_api/mcp/`;
        	mcpUrl = validateUrl(mcpUrl);
        	await callGradioToolWithHeaders(mcpUrl, "tool", {}, hfToken, {});
        }
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-CREDFWD" for f in findings), findings


def test_credfwd_js_wrapper_path_suffix_only_known_false_positive(tmp_path):
    """Documents, rather than hides, a real false-positive class this
    milestone's own false-positive sweep found against a real target
    (doit-mcp-server, see MILESTONE_CREDFWD_JS_STATUS.md): a shared
    authenticated-API-request helper called with a token-named argument is
    a common, LEGITIMATE pattern when the destination's HOST is fixed and
    only a PATH SUFFIX is tool-controlled -- this shape is structurally
    identical to the real bug from the wrapper-call alternative's own
    point of view (a taint-reachable destination argument plus a
    credential-shaped argument on the same call), so it still fires. The
    assertion here is deliberately "it fires, at medium confidence with an
    explicit caveat" -- not "it doesn't fire" -- documenting the known,
    accepted tradeoff rather than silently encoding a fix this milestone
    does not actually implement."""
    _write(
        tmp_path / "requests.ts",
        """
        const ALERTS_BASE_URL = "https://api.example.com/v1/alerts";

        export async function getAlert(alertId: string, token: string): Promise<unknown> {
        	const url = `${ALERTS_BASE_URL}/${encodeURIComponent(alertId)}`;
        	const data = await makeApiRequest(url, token, { method: "GET" });
        	return data;
        }
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-CREDFWD"]
    assert any(h.location.startswith("requests.ts:") for h in hits), findings
    hit = next(h for h in hits if h.location.startswith("requests.ts:"))
    assert hit.confidence == "medium"
    assert "PATH SUFFIX" in hit.description


# --------------------------------------------------------------------------
# Kotlin (Kotlin-support milestone). Real per-tool shape modeled directly on
# JetBrains/teamcity-mcp's own real `McpTool` implementations (see
# entrypoints_kotlin.py's own module docstring and
# bench/KOTLIN_SUPPORT_STATUS.md for the full validation record against
# that real target).
# --------------------------------------------------------------------------


def _kotlin_tool(tmp_path, filename, body_line):
    """Write one minimal, real-shaped Kotlin `McpTool` implementation --
    same `companion object { const val NAME = ... }` / `override val name =
    NAME` / `override suspend fun execute(arguments: JsonObject?)` shape
    every real teamcity-mcp tool class uses -- with `body_line` as the one
    line of tool-specific logic."""
    _write(
        tmp_path / filename,
        f"""
        class SomeTool : McpTool {{
            companion object {{
                internal const val NAME = "some_tool"
            }}
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {{
                val input = arguments?.get("input")?.jsonPrimitive?.content
                {body_line}
                return McpToolResult.success("ok")
            }}
        }}
        """,
    )


def test_kotlin_cmdi_processbuilder_vararg_last_arg_is_caught(tmp_path):
    """The real-world ProcessBuilder vararg shape (`"sh", "-c", $CMD` --
    tainted value LAST, not first, unlike Python's subprocess.run($CMD,
    ...)) -- confirmed empirically necessary; see _VULN_CLASSES_KOTLIN's own
    module comment for the pattern that was tried and dropped."""
    _kotlin_tool(tmp_path, "BuildTool.kt", 'val pb = ProcessBuilder("sh", "-c", input)\n                pb.start()')
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-CMDI"]
    assert any(h.location.startswith("BuildTool.kt:") for h in hits), findings


def test_kotlin_pathtrav_file_is_caught_and_normalize_clears_it(tmp_path):
    _write(
        tmp_path / "FileTool.kt",
        """
        class FileTool : McpTool {
            companion object {
                internal const val NAME = "file_tool"
            }
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                val path = arguments?.get("path")?.jsonPrimitive?.content
                val unsafe = File(path)
                unsafe.readText()
                val safe = File(path).canonicalFile
                val safeResolved = Paths.get(path).normalize()
                Files.readAllBytes(safeResolved)
                return McpToolResult.success("ok")
            }
        }
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-PATHTRAV" and f.location.startswith("FileTool.kt:")]
    assert any("File(path)" in h.evidence for h in hits), findings
    assert not any("safeResolved" in h.evidence for h in hits), findings


def test_kotlin_ssrf_url_and_uri_create_are_caught(tmp_path):
    _kotlin_tool(
        tmp_path,
        "HttpTool.kt",
        'val conn = URL(input).openConnection()\n                val uri = URI.create(input)',
    )
    findings = run_static_taint_scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "TAINT-SSRF" and f.location.startswith("HttpTool.kt:")]
    assert len(hits) == 2, findings


def test_kotlin_finding_has_source_and_sink_steps(tmp_path):
    """reconstruct_path_kotlin's own minimal, honest evidence path (see its
    docstring): exactly a source step (the enclosing `execute()` method's
    own signature line) and a sink step (the flagged line) -- no
    intermediate assignment trace the way Python/JS findings get."""
    _kotlin_tool(tmp_path, "CmdTool.kt", 'val pb = ProcessBuilder(input)\n                pb.start()')
    findings = run_static_taint_scan(tmp_path)
    hit = next(f for f in findings if f.rule_id == "TAINT-CMDI")
    assert hit.taint_path is not None
    assert [s["kind"] for s in hit.taint_path] == ["source", "sink"]
    assert "override suspend fun execute" in hit.taint_path[0]["code"]


def test_kotlin_add_tool_dispatch_wrapper_alone_is_not_a_false_positive(tmp_path):
    """The real teamcity-mcp McpServerConfigurator.kt shape: a generic
    per-tool `server.addTool(...) { request -> tool.execute(request.
    arguments) }` dispatch loop that just forwards into another (here,
    non-existent-in-this-fixture) function -- must not itself produce a
    Kotlin taint finding, since `_source_block_kotlin` deliberately never
    anchors a source on a shape-A entrypoint (see that function's own
    module comment)."""
    _write(
        tmp_path / "McpServerConfigurator.kt",
        """
        class McpServerConfigurator {
            fun configureServer(): Server {
                for (tool in getEnabledTools()) {
                    server.addTool(name = tool.name, description = tool.description) { request ->
                        tool.execute(request.arguments)
                    }
                }
                return server
            }
        }
        """,
    )
    assert run_static_taint_scan(tmp_path) == []


def test_kotlin_teamcity_buildlogtool_real_shape_is_a_true_negative(tmp_path):
    """Regression test for the real, confirmed result this milestone's own
    validation found: JetBrains/teamcity-mcp's real BuildLogTool.kt (see
    bench/ledger/entries/jetbrains-teamcity-mcp-buildlogtool-refuted.json
    and bench/KOTLIN_SUPPORT_STATUS.md) passes its tainted `buildId`
    argument only into `BuildsManager.findBuildInstanceById(buildId)` -- not
    one of this project's own CMDI/PATHTRAV/SSRF sink vocabularies at all.
    Kotlin support recovers the entrypoint (proven separately by
    test_entrypoints_kotlin.py and this milestone's own real-target run),
    but must not manufacture a static-taint finding where the real source
    has none of these 3 sinks reachable -- confirming the existing
    refutation's own claim (no explicit permission check IN THIS FILE) is
    an orthogonal question this project's static-taint tier was never
    positioned to answer either way."""
    _write(
        tmp_path / "BuildLogTool.kt",
        """
        class BuildLogTool(
            private val buildsManager: BuildsManager? = null
        ) : McpTool {
            companion object {
                internal const val NAME = "teamcity_build_log"
            }
            override val name = NAME
            override suspend fun execute(arguments: JsonObject?): McpToolResult {
                val buildIdStr = arguments?.get("buildId")?.jsonPrimitive?.content
                val buildId = buildIdStr?.toLongOrNull()
                    ?: return McpToolResult.error("invalid")
                val manager = buildsManager ?: return McpToolResult.error("unavailable")
                val build = manager.findBuildInstanceById(buildId)
                    ?: return McpToolResult.error("not found")
                return McpToolResult.success(build.toString())
            }
        }
        """,
    )
    assert run_static_taint_scan(tmp_path) == []
