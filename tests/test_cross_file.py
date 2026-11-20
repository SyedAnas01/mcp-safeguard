"""Tests for the bounded, single-hop cross-file resolution milestone
(cross_file.py, wired into taint_scanner.py's `run_static_taint_scan`,
`reconstruct_path`, and `reconstruct_path_js`).

Same discipline as test_taint_scanner.py: real semgrep, real tmp_path repos
reproducing the actual real-world shapes this milestone validates against
(catrinmdonnelly/royalmail-mcp's get_label -> saveLabelToDisk split across
two files, and a constructed TAINT-IDOR cross-file-check analog of the same
structural gap) -- not mocked, so these tests prove the generated rules and
reconstructed paths actually work end to end.
"""

import shutil
import textwrap

import pytest

from mcp_safeguard.scanner.taint_scanner import run_static_taint_scan

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


# --------------------------------------------------------------------------
# Python: recall gain (a real bug reachable only via cross-file resolution)
# --------------------------------------------------------------------------


def test_python_cross_file_pathtrav_is_caught(tmp_path):
    """The royalmail-mcp shape in Python: the MCP handler forwards its own
    parameter into a function imported from another file, and the actual
    filesystem sink lives entirely in that OTHER file -- unreachable by
    same-file-only entrypoint recovery/rule generation."""
    _write(
        tmp_path / "utils" / "labels.py",
        """
        def save_label_to_disk(filename_stem, extension="pdf"):
            filename = f"{filename_stem}.{extension}"
            full_path = "/base/" + filename
            with open(full_path, "w") as f:
                f.write("data")
            return full_path
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from utils.labels import save_label_to_disk

        @mcp.tool()
        def get_label(order_identifier: str) -> dict:
            path = save_label_to_disk(f"rm-{order_identifier}")
            return {"path": path}
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-PATHTRAV" and f.tier == "S" for f in findings), findings
    finding = next(f for f in findings if f.rule_id == "TAINT-PATHTRAV")
    assert finding.location.startswith("utils/labels.py:")
    assert finding.taint_path is not None
    kinds = [s["kind"] for s in finding.taint_path]
    assert kinds[0] == "source"
    assert "cross_file_call" in kinds
    assert kinds[-1] == "sink"
    # The origin entrypoint's own file/line must be visible in the
    # prepended steps -- full auditability, per the milestone's own spec.
    assert finding.taint_path[0]["file"] == "server.py"
    assert finding.taint_path[-1]["file"] == "utils/labels.py"


def test_python_cross_file_recall_stays_silent_when_callee_sanitizes(tmp_path):
    """Same shape as above, but the callee genuinely validates the path --
    must NOT fire. Precision check: cross-file resolution must recognize a
    real sanitizer one hop away, not just chase every cross-file call into
    a finding."""
    _write(
        tmp_path / "utils" / "labels.py",
        """
        import os

        def save_label_to_disk(filename_stem, extension="pdf"):
            filename = f"{filename_stem}.{extension}"
            full_path = os.path.realpath("/base/" + filename)
            if not full_path.startswith("/base/"):
                raise ValueError("bad path")
            with open(full_path, "w") as f:
                f.write("data")
            return full_path
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from utils.labels import save_label_to_disk

        @mcp.tool()
        def get_label(order_identifier: str) -> dict:
            path = save_label_to_disk(f"rm-{order_identifier}")
            return {"path": path}
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-PATHTRAV" for f in findings), findings


# --------------------------------------------------------------------------
# Python: TAINT-IDOR false-positive fix (a real check exists, one hop away)
# --------------------------------------------------------------------------


def test_python_cross_file_idor_check_suppresses_false_positive(tmp_path):
    """The auth-check function called at the site is NOT itself one of
    IDOR_AUTH_CHECK_NAMES (a repo-specific wrapper name), but it calls a
    recognized check name one hop into another file -- must be recognized
    as a real check, not reported as 'no check found'."""
    _write(
        tmp_path / "auth.py",
        """
        def check_access(resource_id, user):
            pass

        def ensure_dataset_owner(resource_id, user):
            check_access(resource_id, user)
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from auth import ensure_dataset_owner

        @mcp.tool()
        def get_dataset(dataset_name: str, user) -> dict:
            ensure_dataset_owner(dataset_name, user)
            record = db.get_dataset(dataset_name)
            return record
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert not any(f.rule_id == "TAINT-IDOR" for f in findings), findings


def test_python_cross_file_idor_still_fires_when_no_real_check_exists(tmp_path):
    """The redis/mcp-redis-shaped control: a cross-file call exists (the
    connection factory), but it takes no resource-scoping argument at all
    -- there is genuinely nothing to check, same-file or cross-file, so
    the finding must still fire. Verifies cross-file resolution doesn't
    over-suppress just because SOME cross-file call is on the path.

    An `auth.py` tenancy-evidence fixture (same idiom as
    test_taint_scanner.py's own IDOR-fix "still flags" tests) is included so
    this test isolates the cross-file mechanism under test from the
    IDOR-fix milestone's own (correct, separately tested) tenancy gate --
    without it, this synthetic single-file-signal project would be
    suppressed by default for having no measured multi-tenancy evidence at
    all, the same real behavior confirmed against the actual redis/mcp-redis
    repo this fixture is shaped after."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "conn.py",
        """
        def get_connection():
            return object()
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from conn import get_connection

        @mcp.tool()
        def delete_key(key: str) -> str:
            r = get_connection()
            result = r.delete(key)
            return str(result)
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-IDOR" for f in findings), findings


# --------------------------------------------------------------------------
# One-hop boundary: a resolved callee that itself needs a SECOND hop must
# not be chased -- the finding stays, marked inconclusive at that point.
# --------------------------------------------------------------------------


def test_python_cross_file_stops_at_one_hop(tmp_path):
    """`outer_check` (one hop from the handler) itself forwards to
    `inner_check` (a second, deeper file) -- this module must not chase
    that second hop. The finding must still be reported (never silently
    dropped), with an explicit `unresolved_deeper_indirection` step.

    `auth.py` tenancy-evidence fixture included (see
    test_python_cross_file_idor_still_fires_when_no_real_check_exists'
    own comment) so this test isolates the one-hop-boundary mechanism from
    the IDOR-fix milestone's separately tested tenancy gate."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "inner_check.py",
        """
        def inner_check(resource_id, user):
            if resource_id not in user.allowed_ids:
                raise PermissionError("no")
        """,
    )
    _write(
        tmp_path / "outer_check.py",
        """
        from inner_check import inner_check

        def outer_check(resource_id, user):
            inner_check(resource_id, user)
        """,
    )
    _write(
        tmp_path / "server.py",
        """
        from outer_check import outer_check

        @mcp.tool()
        def get_dataset(dataset_name: str, user) -> dict:
            outer_check(dataset_name, user)
            record = db.get_dataset(dataset_name)
            return record
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    idor = [f for f in findings if f.rule_id == "TAINT-IDOR"]
    assert idor, findings
    steps = idor[0].taint_path
    assert any(s["kind"] == "unresolved_deeper_indirection" for s in steps), steps


def test_python_cross_file_external_import_is_inconclusive_not_a_free_pass(tmp_path):
    """A guard call imported from a THIRD-PARTY package (not resolvable to
    a local file) must be marked external_call_unresolved and must NOT
    clear the finding -- inconclusive is not the same as "safe".

    `auth.py` tenancy-evidence fixture included (see
    test_python_cross_file_idor_still_fires_when_no_real_check_exists'
    own comment) so this test isolates the external-import-unresolved
    mechanism from the IDOR-fix milestone's separately tested tenancy gate."""
    _write(
        tmp_path / "auth.py",
        "class User:\n    pass\n",
    )
    _write(
        tmp_path / "server.py",
        """
        from some_third_party_sdk import verify_thing

        @mcp.tool()
        def get_dataset(dataset_name: str, user) -> dict:
            verify_thing(dataset_name, user)
            record = db.get_dataset(dataset_name)
            return record
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    idor = [f for f in findings if f.rule_id == "TAINT-IDOR"]
    assert idor, findings
    steps = idor[0].taint_path
    assert any(s["kind"] == "external_call_unresolved" for s in steps), steps


# --------------------------------------------------------------------------
# JS/TS: the same recall gain, in the language the real holdout target
# (catrinmdonnelly/royalmail-mcp) is actually written in.
# --------------------------------------------------------------------------


def test_js_cross_file_pathtrav_is_caught(tmp_path):
    """A named-import, object-literal-argument cross-file call -- the
    common real shape (get_label forwarding {filenameStem: ...} into a
    destructured parameter of an imported save function)."""
    _write(
        tmp_path / "utils" / "labels.js",
        """
        export async function saveLabelToDisk({ labelBase64, filenameStem, extension = 'pdf' }) {
          const filename = `${filenameStem}.${extension}`;
          const fullPath = '/base/' + filename;
          const buffer = Buffer.from(labelBase64, 'base64');
          await writeFile(fullPath, buffer);
          return fullPath;
        }
        """,
    )
    _write(
        tmp_path / "server.js",
        """
        import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
        import { saveLabelToDisk } from './utils/labels.js';

        server.tool(
          'get_label',
          'desc',
          { orderIdentifier: z.string() },
          async ({ orderIdentifier }) => {
            const filePath = await saveLabelToDisk({
              labelBase64: 'xx',
              filenameStem: `rm-${orderIdentifier}`,
              extension: 'pdf',
            });
            return { filePath };
          }
        );
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-PATHTRAV" and f.tier == "S" for f in findings), findings
    finding = next(f for f in findings if f.rule_id == "TAINT-PATHTRAV")
    assert finding.location.startswith("utils/labels.js:")
    kinds = [s["kind"] for s in finding.taint_path]
    assert "cross_file_call" in kinds
    assert kinds[-1] == "sink"


def test_js_cross_file_resolves_ts_extension_import_specifier(tmp_path):
    """Adversary-repo-read milestone: TypeScript's own ESM convention
    (`"moduleResolution": "node16"`/`"bundler"`) writes an import specifier
    with the extension the file will have AFTER compilation
    (`'./utils/labels.js'`) even though the real on-disk source is
    `labels.ts` -- confirmed as a real, previously-unresolved gap against
    auth0-mcp-server's own real `applications.ts`/`response-masker.ts`
    import (see cross_file.py's own `resolve_js_module_file` docstring).
    Same shape as `test_js_cross_file_pathtrav_is_caught` above, except the
    real file is `.ts` and the specifier says `.js`."""
    _write(
        tmp_path / "utils" / "labels.ts",
        """
        export async function saveLabelToDisk({ labelBase64, filenameStem, extension = 'pdf' }: any) {
          const filename = `${filenameStem}.${extension}`;
          const fullPath = '/base/' + filename;
          const buffer = Buffer.from(labelBase64, 'base64');
          await writeFile(fullPath, buffer);
          return fullPath;
        }
        """,
    )
    _write(
        tmp_path / "server.ts",
        """
        import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
        import { saveLabelToDisk } from './utils/labels.js';

        server.tool(
          'get_label',
          'desc',
          { orderIdentifier: z.string() },
          async ({ orderIdentifier }: any) => {
            const filePath = await saveLabelToDisk({
              labelBase64: 'xx',
              filenameStem: `rm-${orderIdentifier}`,
              extension: 'pdf',
            });
            return { filePath };
          }
        );
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    assert any(f.rule_id == "TAINT-PATHTRAV" and f.tier == "S" for f in findings), findings
    finding = next(f for f in findings if f.rule_id == "TAINT-PATHTRAV")
    assert finding.location.startswith("utils/labels.ts:")
    kinds = [s["kind"] for s in finding.taint_path]
    assert "cross_file_call" in kinds


def test_js_cross_file_does_not_taint_unrelated_sibling_parameter(tmp_path):
    """Precision check for the rule-generation side: the hop's synthetic
    source must be scoped to the SPECIFIC mapped parameter
    (`filenameStem`), not every parameter of the shared callee -- an
    unrelated sibling parameter (`otherPath`, independently a path used in
    a dangerous sink) that was never forwarded from the real entrypoint
    must NOT be flagged."""
    _write(
        tmp_path / "utils" / "labels.js",
        """
        export async function saveLabelToDisk({ filenameStem, otherPath }) {
          const filename = `${filenameStem}.pdf`;
          const fullPath = '/base/' + filename;
          await writeFile(fullPath, Buffer.from('x'));
          await writeFile(otherPath, Buffer.from('y'));
          return fullPath;
        }
        """,
    )
    _write(
        tmp_path / "server.js",
        """
        import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
        import { saveLabelToDisk } from './utils/labels.js';

        server.tool(
          'get_label',
          'desc',
          { orderIdentifier: z.string() },
          async ({ orderIdentifier }) => {
            const filePath = await saveLabelToDisk({
              filenameStem: `rm-${orderIdentifier}`,
              otherPath: '/fixed/constant/path.pdf',
            });
            return { filePath };
          }
        );
        """,
    )
    findings = run_static_taint_scan(tmp_path)
    pathtrav = [f for f in findings if f.rule_id == "TAINT-PATHTRAV"]
    # The real forwarded-parameter sink (fullPath, built from filenameStem)
    # must still be caught...
    assert any(f.location.endswith(":5") for f in pathtrav), pathtrav
    # ...but the otherPath sink (line 6), never forwarded from the real
    # entrypoint, must not be -- otherwise this milestone would be tainting
    # the whole shared helper function instead of just the mapped parameter,
    # exactly the "following into a huge shared utils file could create
    # noise" risk its own task spec warned against.
    assert not any(f.location.endswith(":6") for f in pathtrav), pathtrav
