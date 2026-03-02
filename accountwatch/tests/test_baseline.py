"""Tests for the baseline diff engine."""

from accountwatch.baseline import diff_contacts


def test_no_change():
    baseline = ["email:user@example.com", "email:backup@example.com"]
    current = ["email:user@example.com", "email:backup@example.com"]
    diff = diff_contacts(baseline, current)
    assert diff["added"] == []
    assert diff["removed"] == []


def test_unauthorized_add():
    """Core detection: attacker adds their email."""
    baseline = ["email:legit@gmail.com"]
    current = ["email:legit@gmail.com", "email:attacker@yahoo.com"]
    diff = diff_contacts(baseline, current)
    assert "email:attacker@yahoo.com" in diff["added"]
    assert diff["removed"] == []


def test_contact_removed():
    baseline = ["email:legit@gmail.com", "email:backup@gmail.com"]
    current = ["email:legit@gmail.com"]
    diff = diff_contacts(baseline, current)
    assert "email:backup@gmail.com" in diff["removed"]
    assert diff["added"] == []


def test_swap_attack():
    """Attacker removes legit contact and adds their own."""
    baseline = ["email:legit@gmail.com"]
    current = ["email:attacker@myyahoo.com"]
    diff = diff_contacts(baseline, current)
    assert "email:attacker@myyahoo.com" in diff["added"]
    assert "email:legit@gmail.com" in diff["removed"]


def test_real_world_meta_incident():
    """Reproduces the exact incident that motivated this tool."""
    baseline = ["email:natorretti11@gmail.com"]
    current = ["email:natorretti11@gmail.com", "email:nsh11@myyahoo.com"]
    diff = diff_contacts(baseline, current)
    assert "email:nsh11@myyahoo.com" in diff["added"]
    assert diff["removed"] == []
