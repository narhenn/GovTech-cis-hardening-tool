import pytest
from src.rules_loader import RulesLoader


VALID_YAML = """
rules:
  - id: "1.1.1.1"
    title: "Ensure cramfs kernel module is not available"
    description: "cramfs should be disabled"
    category: "filesystem"
    command: "modprobe -n -v cramfs 2>&1"
    expected: ""
    match_type: "absent"
    remediation: "echo 'install cramfs /bin/false' >> /etc/modprobe.d/cramfs.conf"
  - id: "5.2.11"
    title: "Ensure SSH PermitRootLogin is disabled"
    description: "Root SSH login should be disabled"
    category: "ssh"
    command: "sshd -T | grep permitrootlogin"
    expected: "permitrootlogin no"
    match_type: "contains"
"""


def test_load_valid(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(VALID_YAML)
    loader = RulesLoader(str(f))
    rules = loader.load()
    assert len(rules) == 2
    assert rules[0]["id"] == "1.1.1.1"


def test_file_not_found():
    with pytest.raises(FileNotFoundError):
        RulesLoader("/doesnt/exist.yaml").load()


def test_skips_incomplete(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("rules:\n  - id: '1'\n    title: 'test'\n")
    assert len(RulesLoader(str(f)).load()) == 0


def test_bad_yaml_structure(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("not_rules:\n  - stuff\n")
    with pytest.raises(ValueError):
        RulesLoader(str(f)).load()


def test_category_filter(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(VALID_YAML)
    loader = RulesLoader(str(f))
    loader.load()
    assert len(loader.get_rules_by_category("ssh")) == 1
    assert len(loader.get_rules_by_category("filesystem")) == 1
    assert len(loader.get_rules_by_category("blah")) == 0
