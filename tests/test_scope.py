"""Tests for scope parsing, validation, and refusal logic."""

import pytest
from pathlib import Path
from umbra.core.models import ScopeConfig
from umbra.core.scope import (
    ScopeRefusalError,
    validate_and_expand_targets,
    parse_scope_file,
    is_loopback,
    is_private_or_link_local,
    is_public_target,
)


def test_loopback_and_private_classification():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("::1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("192.168.1.1") is False

    assert is_private_or_link_local("10.0.0.1") is True
    assert is_private_or_link_local("172.16.0.5") is True
    assert is_private_or_link_local("192.168.1.50") is True
    assert is_private_or_link_local("169.254.1.1") is True
    assert is_private_or_link_local("8.8.8.8") is False


def test_public_target_refusal_without_authorized_by():
    # Public IP without scope config should raise ScopeRefusalError with exit code 2
    with pytest.raises(ScopeRefusalError) as exc_info:
        validate_and_expand_targets(["8.8.8.8"], scope=None, confirm_authorized=False)
    assert exc_info.value.exit_code == 2
    assert "requires a scope file with an 'authorized_by' field" in str(exc_info.value)


def test_public_target_refusal_without_confirm_flag():
    # Public IP with authorized_by in scope, but missing --confirm-authorized
    scope = ScopeConfig(
        label="test-scope",
        authorized_by="Security Team Lead",
        targets=["8.8.8.8"]
    )
    with pytest.raises(ScopeRefusalError) as exc_info:
        validate_and_expand_targets([], scope=scope, confirm_authorized=False)
    assert exc_info.value.exit_code == 2
    assert "requires '--confirm-authorized' flag" in str(exc_info.value)


def test_public_target_allowed_when_fully_authorized():
    scope = ScopeConfig(
        label="test-scope",
        authorized_by="Security Team Lead",
        targets=["8.8.8.8"]
    )
    targets = validate_and_expand_targets([], scope=scope, confirm_authorized=True)
    assert targets == ["8.8.8.8"]


def test_private_and_loopback_allowed_by_default():
    targets = validate_and_expand_targets(["127.0.0.1", "192.168.1.10"])
    assert "127.0.0.1" in targets
    assert "192.168.1.10" in targets


def test_cidr_expansion_and_excluded_filtering():
    scope = ScopeConfig(
        label="lab-network",
        authorized_by="Lab Admin",
        targets=["192.168.1.0/30"],
        excluded=["192.168.1.2"]
    )
    expanded = validate_and_expand_targets([], scope=scope, confirm_authorized=False)
    # /30 has hosts .1 and .2 (.0 network, .3 broadcast)
    assert "192.168.1.1" in expanded
    assert "192.168.1.2" not in expanded


def test_parse_scope_file(tmp_path: Path):
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text(
        """
label: staging-scan
authorized_by: SecOps Director
targets:
  - 10.0.0.0/24
  - 127.0.0.1
excluded:
  - 10.0.0.1
notes: Test run
""",
        encoding="utf-8"
    )
    cfg = parse_scope_file(scope_yaml)
    assert cfg.label == "staging-scan"
    assert cfg.authorized_by == "SecOps Director"
    assert "127.0.0.1" in cfg.targets
    assert "10.0.0.1" in cfg.excluded

