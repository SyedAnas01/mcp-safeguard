"""Tests for Stage 1 MCP entrypoint recovery (Go, `entrypoints_go.py`).

Go had ZERO language support anywhere in this pipeline before this
milestone. These tests are modeled directly on the two real, campaign
-audited Go MCP servers this module was validated against -- see
`bench/GO_ENTRYPOINTS_STATUS.md` for the real before/after entrypoint
counts against the actual cloned repos (digitalocean-labs/mcp-digitalocean,
datadog-labs/datadog-code-security-mcp)."""

import textwrap

from mcp_safeguard.scanner.entrypoints_go import recover_go_entrypoints


def _write(path, text):
    path.write_text(textwrap.dedent(text))


def test_server_tool_struct_elided_type_is_recovered(tmp_path):
    """The real digitalocean-labs/mcp-digitalocean shape: a `Tools()` method
    returning `[]server.ServerTool{ {Handler: ..., Tool: mcp.NewTool(...)},
    ... }` -- each element's OWN type is elided (Go infers it from the
    slice's element type), which an earlier version of this module missed
    entirely because tree-sitter-go represents an elided element as a bare
    `literal_value` with no `composite_literal` wrapper at all."""
    _write(
        tmp_path / "evaluation_tools.go",
        """
        package genai

        func (et *EvaluationTool) createEvaluationDataset(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            filePath, ok := args["file_path"].(string)
            return nil, nil
        }

        func (et *EvaluationTool) Tools() []server.ServerTool {
            return []server.ServerTool{
                {
                    Handler: et.createEvaluationDataset,
                    Tool: mcp.NewTool(
                        "genai-create-evaluation-dataset",
                        mcp.WithDescription("Create an evaluation dataset."),
                    ),
                },
            }
        }
        """,
    )
    eps = recover_go_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "createEvaluationDataset"
    assert ep.sdk_shape == "server_tool_struct"
    assert ep.confidence == "high"
    assert ep.parameter_names == ["ctx", "req"]


def test_add_tool_call_handler_in_sibling_file_same_package_is_recovered(tmp_path):
    """The real datadog-labs/datadog-code-security-mcp shape: tools are
    registered in one file (`start.go`) via `s.AddTool(mcp.Tool{Name: ...},
    handler)`, but every handler is DEFINED in a separate sibling file of
    the SAME package (`handlers.go`) -- a same-file-only resolver (the
    Python/JS discipline this module deliberately departs from for Go, see
    its module docstring) recovers 0 entrypoints here; this is the exact
    real-world case that discipline was corrected for."""
    _write(
        tmp_path / "start.go",
        """
        package main

        func registerSecurityTools(s *server.MCPServer) {
            s.AddTool(
                mcp.Tool{
                    Name:        "datadog_generate_sbom",
                    Description: "Generate a comprehensive SBOM.",
                },
                handleGenerateSBOM,
            )
        }
        """,
    )
    _write(
        tmp_path / "handlers.go",
        """
        package main

        func handleGenerateSBOM(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            path := ensurePath(request)
            return nil, nil
        }
        """,
    )
    eps = recover_go_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "handleGenerateSBOM"
    assert ep.sdk_shape == "add_tool_call"
    assert ep.confidence == "high"
    assert str(ep.file).endswith("handlers.go")  # recorded at the handler's OWN file, not start.go


def test_add_tool_call_official_sdk_pointer_tool_literal_is_recovered(tmp_path):
    """The official `github.com/modelcontextprotocol/go-sdk` shape (real
    usage confirmed in docker/mcp-gateway's own example servers):
    `server.AddTool(&mcp.Tool{Name: ...}, recv.method)`, with the tool
    literal `&`-wrapped and the handler a `recv.Method` selector resolved
    against the enclosing method's own receiver."""
    _write(
        tmp_path / "main.go",
        """
        package main

        func (vs *VectorServer) registerTools(server *mcp.Server) {
            server.AddTool(
                &mcp.Tool{
                    Name:        "list_collections",
                    Description: "List all vector collections.",
                },
                vs.handleListCollections,
            )
        }

        func (vs *VectorServer) handleListCollections(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            return nil, nil
        }
        """,
    )
    eps = recover_go_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "handleListCollections"
    assert ep.sdk_shape == "add_tool_call"
    assert ep.confidence == "high"


def test_tool_name_anchored_fallback_is_recovered(tmp_path):
    """Shape C, the generic fallback: a custom wrapper type neither named
    `Tool`/`ServerTool` nor registered via an `AddTool`-named call, but
    still pairing a `Name` field with a sibling `Handler` field on the same
    literal."""
    _write(
        tmp_path / "registry.go",
        """
        package registry

        func buildRegistrations() []Registration {
            return []Registration{
                {Name: "custom_tool", Handler: runCustomTool},
            }
        }

        func runCustomTool(ctx context.Context, args map[string]any) error {
            return nil
        }
        """,
    )
    eps = recover_go_entrypoints(tmp_path)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.function_name == "runCustomTool"
    assert ep.sdk_shape == "tool_name_anchored"
    assert ep.confidence == "medium"


def test_composite_literal_with_name_but_no_handler_is_not_an_entrypoint(tmp_path):
    """Over-match guard: a `Name`-bearing literal with no handler
    -vocabulary sibling field (an ordinary tool-schema struct, not a
    registration) must not produce an entrypoint."""
    _write(
        tmp_path / "schema.go",
        """
        package genai

        func schema() mcp.Tool {
            return mcp.Tool{Name: "genai-list-evaluation-metrics", Description: "List metrics."}
        }
        """,
    )
    assert recover_go_entrypoints(tmp_path) == []


def test_add_tool_call_missing_name_field_is_not_an_entrypoint(tmp_path):
    """Over-match guard: an `AddTool`-named call whose tool literal has no
    `Name` field at all must not be treated as a registration."""
    _write(
        tmp_path / "start.go",
        """
        package main

        func register(s *server.MCPServer) {
            s.AddTool(mcp.Tool{Description: "no name field"}, handleThing)
        }

        func handleThing(ctx context.Context) error {
            return nil
        }
        """,
    )
    assert recover_go_entrypoints(tmp_path) == []


def test_selector_handler_with_mismatched_receiver_is_not_resolved(tmp_path):
    """Over-match guard: `otherThing.handleFoo` inside a method whose OWN
    receiver is named `vs`, not `otherThing` -- this module resolves a
    `recv.Method` selector ONLY against the enclosing method's own
    receiver (see module docstring), so an unrelated local/package-level
    variable of the same shape must be left unresolved, not guessed at."""
    _write(
        tmp_path / "main.go",
        """
        package main

        func (vs *VectorServer) registerTools(server *mcp.Server, otherThing *Helper) {
            server.AddTool(
                &mcp.Tool{Name: "list_collections"},
                otherThing.handleFoo,
            )
        }

        func (h *Helper) handleFoo(ctx context.Context) error {
            return nil
        }
        """,
    )
    assert recover_go_entrypoints(tmp_path) == []


def test_test_go_files_are_skipped(tmp_path):
    """`_test.go` files are never part of a real server binary and must be
    skipped outright, even though they can contain the exact same
    registration shapes (mock servers, table-driven registration tests)."""
    _write(
        tmp_path / "main_test.go",
        """
        package main

        func TestRegister(t *testing.T) {
            s.AddTool(mcp.Tool{Name: "fake_tool"}, fakeHandler)
        }

        func fakeHandler(ctx context.Context) error {
            return nil
        }
        """,
    )
    assert recover_go_entrypoints(tmp_path) == []
