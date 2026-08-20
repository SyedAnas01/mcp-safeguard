"""Tests for the source-tree scanner (SRC-001..SRC-004)."""

from mcp_shield.scanner.source_scanner import scan_source_tree


def test_src001_go_roundtrip_without_checkredirect_is_flagged(tmp_path):
    """
    A custom RoundTripper that re-applies Authorization on every hop, with no
    CheckRedirect anywhere in the file to strip it on a host change, is the
    exact shape that let a bearer token follow a cross-host redirect.
    """
    (tmp_path / "transport.go").write_text(
        """
        package auth

        func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
            req.Header.Set("Authorization", "Bearer "+t.token)
            return t.base.RoundTrip(req)
        }
        """
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-001" for f in findings), (
        f"Expected SRC-001, got: {findings}"
    )


def test_src001_go_roundtrip_with_checkredirect_is_not_flagged(tmp_path):
    """Same shape, but the file also has a CheckRedirect guard -- not a finding."""
    (tmp_path / "transport.go").write_text(
        """
        package auth

        func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
            req.Header.Set("Authorization", "Bearer "+t.token)
            return t.base.RoundTrip(req)
        }

        var client = &http.Client{CheckRedirect: stripAuthOnHostChange}
        """
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-001" for f in findings), (
        f"Did not expect SRC-001 with a CheckRedirect present, got: {findings}"
    )


def test_src002_httpx_follow_redirects_with_bearer_is_flagged(tmp_path):
    """httpx client with follow_redirects=True plus a Bearer header can leak the
    token to a foreign host on redirect -- the Python analogue of SRC-001."""
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        client = httpx.Client(
            follow_redirects=True,
            headers={"Authorization": f"Bearer {token}"},
        )
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-002" for f in findings), (
        f"Expected SRC-002, got: {findings}"
    )


def test_src002_httpx_without_follow_redirects_is_not_flagged(tmp_path):
    """Same headers, but redirects are not followed -- not a finding."""
    (tmp_path / "client.py").write_text(
        '''
        import httpx

        client = httpx.Client(headers={"Authorization": f"Bearer {token}"})
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-002" for f in findings), (
        f"Did not expect SRC-002 without follow_redirects=True, got: {findings}"
    )


def test_src003_string_only_readonly_check_is_flagged(tmp_path):
    """Gating read-only mode on a `.startswith('select')` check, with no
    database-level read-only transaction anywhere in the file, is defeated by
    leading comments, CTEs that write, and stacked statements."""
    (tmp_path / "db.py").write_text(
        '''
        def run(query: str):
            if not query.strip().lower().startswith("select"):
                raise PermissionError("read-only mode")
            return execute(query)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-003" for f in findings), (
        f"Expected SRC-003, got: {findings}"
    )


def test_src003_with_db_level_readonly_is_not_flagged(tmp_path):
    """Same string check, but the file also sets a real read-only transaction
    at the database layer -- the string check is now a secondary guard, not
    the only enforcement, so this is not a finding."""
    (tmp_path / "db.py").write_text(
        '''
        def run(query: str):
            if not query.strip().lower().startswith("select"):
                raise PermissionError("read-only mode")
            conn.execute("SET TRANSACTION READ ONLY")
            return execute(query)
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-003" for f in findings), (
        f"Did not expect SRC-003 with a DB-level read-only transaction present, "
        f"got: {findings}"
    )


def test_src004_credential_to_interpolated_host_is_flagged(tmp_path):
    """A server-held access token placed as the connection password while the
    destination host is an interpolated variable is the confused-deputy shape:
    if that host is caller-influenced and unvalidated, the credential goes to
    whatever host the caller names."""
    (tmp_path / "connect.cs").write_text(
        '''
        var connStr = $"Host={targetHost};Port=1433;Password={accessToken}";
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert any(f.rule_id == "SRC-004" for f in findings), (
        f"Expected SRC-004, got: {findings}"
    )


def test_src004_credential_to_fixed_host_is_not_flagged(tmp_path):
    """Same password pattern, but the host is a fixed string literal, not an
    interpolated/caller-influenced variable -- not a finding."""
    (tmp_path / "connect.cs").write_text(
        '''
        var connStr = "Host=db.internal.example.com;Port=1433;Password=" + accessToken;
        '''
    )
    findings = scan_source_tree(tmp_path)
    assert not any(f.rule_id == "SRC-004" for f in findings), (
        f"Did not expect SRC-004 with a fixed host literal, got: {findings}"
    )


def test_empty_tree_produces_no_findings(tmp_path):
    """A directory with no matching source files returns an empty list, not
    an error."""
    (tmp_path / "README.md").write_text("nothing to see here")
    assert scan_source_tree(tmp_path) == []


def test_skips_vendored_and_test_paths(tmp_path):
    """A vulnerable-looking pattern inside node_modules/vendor/dist/test paths
    is noise, not a real finding in the project's own code -- must be skipped."""
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "client.py").write_text(
        '''
        import httpx
        client = httpx.Client(follow_redirects=True, headers={"Authorization": f"Bearer {t}"})
        '''
    )
    assert scan_source_tree(tmp_path) == []


def test_skips_top_level_tests_dir_scanned_from_a_relative_root(tmp_path, monkeypatch):
    """Regression: scanning with a RELATIVE root (e.g. ".") whose own top-level
    "tests/" dir has no leading slash in the yielded relative path -- a naive
    substring check like `"/tests/" in str(path)` misses this case even though
    an absolute-path check would have caught it. Path-component matching must
    not depend on how the root was spelled."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_client.py").write_text(
        '''
        import httpx
        client = httpx.Client(follow_redirects=True, headers={"Authorization": f"Bearer {t}"})
        '''
    )
    monkeypatch.chdir(tmp_path)
    assert scan_source_tree(".") == []
