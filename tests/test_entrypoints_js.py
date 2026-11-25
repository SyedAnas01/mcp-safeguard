"""Tests for Stage 1 MCP entrypoint recovery -- tool-name anchoring
(shapes F/G/H, entrypoints_js.py). No dedicated test file for
`recover_js_entrypoints` existed before this milestone (it was exercised
only indirectly via test_pipeline.py/test_threat_model.py/test_cross_file.py)
-- these are the first direct unit tests for it, added alongside the new
anchoring shapes. See bench/TOOLNAME_ANCHOR_STATUS.md for the real holdout
targets each shape is modeled on."""

import textwrap

from mcp_safeguard.scanner.entrypoints_js import recover_js_entrypoints


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def test_object_literal_name_and_handler_registry_is_recovered(tmp_path):
    """The real Aiven-Open/mcp-aiven shape: an array of `{name, handler}`
    object literals, where `name`'s value is an enum member declared in a
    DIFFERENT file (so it can never resolve to a literal here) -- the
    structural name-key/handler-key pairing alone must still be enough."""
    _write(
        tmp_path / "handlers.ts",
        """
        import { PgToolName } from './types.js';

        export function createPgCustomTools(client) {
          return [
            {
              name: PgToolName.Read,
              handler: async (params, context) => {
                return executePgQuery(client, params);
              },
            },
          ];
        }
        """,
    )
    eps = recover_js_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.sdk_shape == "object_literal_registry"
    assert ep.confidence == "medium"
    assert ep.parameter_names == ["params", "context"]


def test_object_literal_with_literal_name_is_also_recovered(tmp_path):
    """The simpler variant where `name:`'s value already IS a string
    literal (no enum hop needed)."""
    _write(
        tmp_path / "tools.ts",
        """
        const tools = [
          { name: "aiven_pg_optimize_query", handler: (params) => doOptimize(params) },
        ];
        """,
    )
    eps = recover_js_entrypoints(tmp_path)
    assert len(eps) == 1
    assert eps[0].sdk_shape == "object_literal_registry"


def test_object_literal_missing_handler_key_is_not_an_entrypoint(tmp_path):
    """Over-match guard: an object literal with a `name:` property but NO
    handler-vocabulary sibling property must not produce an entrypoint."""
    _write(
        tmp_path / "schema.ts",
        """
        const toolSchema = { name: "aiven_pg_read", description: "read-only query" };
        """,
    )
    assert recover_js_entrypoints(tmp_path) == []


def test_class_static_tool_name_with_execute_method_is_recovered(tmp_path):
    """The real mongodb-mcp-server shape: a STATIC `toolName` field paired
    with an `execute()` method that has ZERO formal parameters (reads from
    `this.session` instead) -- must still be recovered, unlike every other
    shape in this module which requires at least one parameter."""
    _write(
        tmp_path / "listConnections.ts",
        """
        export class ListConnectionsTool extends MongoDBToolBase {
            static toolName = "list-connections";

            protected override async execute(): Promise<ToolResult> {
                const entries = await this.session.connectionRegistry.find();
                return { content: entries };
            }
        }
        """,
    )
    eps = recover_js_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "execute"
    assert ep.parameter_names == []
    assert ep.sdk_shape == "class_attribute_registration"
    assert ep.confidence == "medium"


def test_class_without_static_name_field_is_not_an_entrypoint(tmp_path):
    """Over-match guard: a class with an `execute` method but NO static
    `toolName`/`name`/`TOOL_NAME` field must not produce an entrypoint."""
    _write(
        tmp_path / "helper.ts",
        """
        export class QueryHelper {
            async execute(query: string) {
                return run(query);
            }
        }
        """,
    )
    assert recover_js_entrypoints(tmp_path) == []


def test_tool_name_keyed_registry_is_recovered_via_schema_array(tmp_path):
    """The real Auth0 shape: a `Tool[]`-shaped array literal (each element
    with a `name:` string-literal property) validates a SEPARATE object
    literal's own keys as real tool names, whose paired values are the
    handlers -- `RESOURCE_SERVER_TOOLS` + `RESOURCE_SERVER_HANDLERS`."""
    _write(
        tmp_path / "resource-servers.ts",
        """
        export const RESOURCE_SERVER_TOOLS = [
          { name: 'auth0_get_resource_server', description: 'Get a resource server' },
          { name: 'auth0_list_resource_servers', description: 'List resource servers' },
        ];

        export const RESOURCE_SERVER_HANDLERS = {
          auth0_get_resource_server: async (request, config) => {
            const resourceServer = await managementClient.resourceServers.get({ id: request.parameters.id });
            return createSuccessResponse(resourceServer);
          },
          auth0_list_resource_servers: async (request, config) => {
            return createSuccessResponse([]);
          },
        };
        """,
    )
    eps = recover_js_entrypoints(tmp_path)
    # Both handlers are anonymous arrow functions (the pair's KEY carries the
    # tool name, not the value) -- `_resolve_handler` names them from the
    # synthetic `<handler@file:line>` placeholder, exactly like the real
    # auth0-mcp-server target's own recovered entrypoints do.
    assert len(eps) == 2
    assert all(e.sdk_shape == "tool_name_keyed_registry" for e in eps)
    assert all(e.confidence == "medium" for e in eps)
    assert all(e.parameter_names == ["request", "config"] for e in eps)


def test_tool_name_keyed_registry_unrelated_key_is_not_an_entrypoint(tmp_path):
    """Over-match guard: an object literal with a function-valued property
    whose key is NOT among the schema array's declared tool names must not
    be treated as a registry entry, even though it sits in the same file
    as a real `Tool[]`-shaped array."""
    _write(
        tmp_path / "resource-servers.ts",
        """
        export const RESOURCE_SERVER_TOOLS = [
          { name: 'auth0_get_resource_server', description: 'Get a resource server' },
        ];

        export const UNRELATED_CALLBACKS = {
          on_startup: async () => {
            return doStartupWork();
          },
        };
        """,
    )
    assert recover_js_entrypoints(tmp_path) == []


# ---------------------------------------------------------------------------
# Transitive (2-hop) cross-file recovery -- serverless-style
# handler -> dispatcher -> tool handler chain (synthetic fixture).
# ---------------------------------------------------------------------------


def _write_chain(tmp_path):
    (tmp_path / "src").mkdir()
    _write(
        tmp_path / "src" / "tools-definition.js",
        """
        import { listProjects } from './list-projects.js';

        export const tools = [
          {
            name: 'list-projects',
            handler: async (args) => {
              return await listProjects(args.dir);
            },
          },
        ];
        """,
    )
    _write(
        tmp_path / "src" / "list-projects.js",
        """
        import { findProjects } from './project-finder.js';

        export async function listProjects(baseDir) {
          const found = await findProjects(baseDir);
          return found.split('\\n');
        }
        """,
    )
    _write(
        tmp_path / "src" / "project-finder.js",
        """
        import { exec } from 'node:child_process';

        export function findProjects(root) {
          return new Promise((resolve) => exec(`find ${root} -name serverless.yml`, (e, out) => resolve(out)));
        }

        export function unrelated(x) {
          return x + 1;
        }
        """,
    )


def test_two_hop_cross_file_callee_is_recovered(tmp_path):
    """The sink function sits two cross-file hops below the registry
    handler. Stage 1 must surface it (tainted param mapped through both
    hops), not stop at the first hop."""
    _write_chain(tmp_path)
    eps = recover_js_entrypoints(tmp_path)
    by_file = {e.file.name: e for e in eps}
    assert "project-finder.js" in by_file
    ep = by_file["project-finder.js"]
    assert ep.function_name == "findProjects"
    assert ep.parameter_names == ["root"]
    assert ep.sdk_shape == "transitive_cross_file_hop"
    assert ep.confidence == "medium"
    # the unrelated function in the same file is not an entrypoint
    assert not any(e.function_name == "unrelated" for e in eps)


def test_two_hop_untainted_argument_is_not_recovered(tmp_path):
    _write_chain(tmp_path)
    _write(
        tmp_path / "src" / "list-projects.js",
        """
        import { findProjects } from './project-finder.js';

        export async function listProjects(baseDir) {
          return (await findProjects('/fixed/path')).split('\\n');
        }
        """,
    )
    eps = recover_js_entrypoints(tmp_path)
    assert not any(e.file.name == "project-finder.js" for e in eps)


def test_transitive_recovery_terminates_on_import_cycle(tmp_path):
    (tmp_path / "a.js").write_text(
        "import { b } from './b.js';\n"
        "export const tools = [{ name: 't', handler: async (args) => b(args.x) }];\n"
    )
    (tmp_path / "b.js").write_text(
        "import { c } from './c.js';\nexport function b(v) { return c(v); }\n"
    )
    (tmp_path / "c.js").write_text(
        "import { b } from './b.js';\nexport function c(w) { return b(w); }\n"
    )
    eps = recover_js_entrypoints(tmp_path)
    assert any(e.file.name == "c.js" for e in eps)


def test_transitive_recovery_is_depth_bounded(tmp_path):
    """Chain a -> f1 -> ... -> f6: recovery adds hops 2-3 only (f2, f3);
    f5 and f6 stay unreached."""
    (tmp_path / "a.js").write_text(
        "import { f1 } from './f1.js';\n"
        "export const tools = [{ name: 't', handler: async (args) => f1(args.x) }];\n"
    )
    for i in range(1, 6):
        (tmp_path / f"f{i}.js").write_text(
            f"import {{ f{i+1} }} from './f{i+1}.js';\nexport function f{i}(v) {{ return f{i+1}(v); }}\n"
        )
    (tmp_path / "f6.js").write_text("export function f6(v) { return v; }\n")
    names = {e.file.name for e in recover_js_entrypoints(tmp_path) if e.sdk_shape == "transitive_cross_file_hop"}
    assert names == {"f2.js", "f3.js"}
