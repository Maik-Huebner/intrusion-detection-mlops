"""Rules and templates of the analyst note (no LLM needed)."""

from ids.api import llm

CTX = {
    "attack_type": "SSH-Patator",
    "family": "Brute Force",
    "type_confidence": 0.99,
    "attack_probability": 1.0,
    "dst_port": 22,
    "protocol": 6,
    "unusual_features": [
        {
            "feature": "Flow Duration",
            "value": 5.0,
            "normal_low": 1200.0,
            "normal_high": 9.8e7,
            "distance": 0.1,
        }
    ],
    "drift_warning": False,
}
GOOD = "SSH-Patator erkannt, ein Brute-Force-Angriff auf Port 22. Flow Duration sehr kurz. Quelle prüfen."


def test_good_note_passes_every_rule():
    assert all(llm.check_rules(GOOD, CTX).values())


def test_note_must_name_the_attack():
    assert llm.check_rules("Ein Angriff wurde erkannt. Bitte prüfen.", CTX)["names_attack_type"] is False


def test_other_attack_family_is_a_hallucination():
    rules = llm.check_rules(GOOD + " Es könnte auch ein DDoS sein.", CTX)
    assert rules["no_other_attack_family"] is False


def test_family_inside_the_type_name_is_fine():
    ctx = CTX | {"attack_type": "DoS Hulk", "family": "DoS"}
    assert llm.check_rules("DoS Hulk erkannt: viele HTTP-Anfragen. Webserver prüfen.", ctx)[
        "no_other_attack_family"
    ]


def test_invented_identifiers_are_rejected():
    for bad in ("von 192.168.10.5", "siehe CVE-2014-0160", "Details: https://example.org"):
        assert llm.check_rules(f"{GOOD} {bad}", CTX)["no_invented_identifiers"] is False


def test_drift_only_when_warned():
    warned = CTX | {"drift_warning": True}
    assert llm.check_rules(GOOD, warned)["drift_only_when_warned"] is False
    assert llm.check_rules(GOOD + " Achtung, Drift: Zuordnung unsicher.", warned)["drift_only_when_warned"]
    # v1 wrote "Drift" without any warning - a false alarm in words
    assert llm.check_rules(GOOD + " Drift prüfen.", CTX)["drift_only_when_warned"] is False


def test_preamble_and_quotes_are_rejected_and_cleaned():
    raw = 'Hier ist die Notiz für den Analysten:\n\n"' + GOOD + '"'
    assert llm.check_rules(raw, CTX)["no_preamble"] is False
    assert llm.clean(raw) == GOOD
    assert llm.check_rules(llm.clean(raw), CTX)["no_preamble"] is True


def test_v2_prompt_mentions_drift_only_with_a_warning(monkeypatch):
    monkeypatch.delenv("LLM_PROMPT_VERSION", raising=False)
    assert "Drift" not in llm.system_prompt(CTX)
    assert "Drift" in llm.system_prompt(CTX | {"drift_warning": True})
    monkeypatch.setenv("LLM_PROMPT_VERSION", "v1")
    assert llm.system_prompt(CTX) == llm.SYSTEM_PROMPT_V1


def test_long_notes_are_rejected():
    assert llm.check_rules(GOOD + " Wort" * 100, CTX)["short"] is False


def test_prompt_carries_findings_and_drift_warning():
    prompt = llm.build_prompt(CTX | {"drift_warning": True})
    assert "SSH-Patator" in prompt and "Brute Force" in prompt and "Zielport 22" in prompt
    assert "Flow Duration" in prompt
    assert "Drift-Monitor" in prompt


def test_template_notes():
    assert "SSH-Patator" in llm.fallback_note(CTX)
    assert "Drift" in llm.fallback_note(CTX | {"drift_warning": True})
    assert "Drift" not in llm.fallback_note(CTX)
    assert llm.no_alarm_note(0.01).startswith("Kein Alarm")


def test_not_configured_without_base_url(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    assert llm.is_configured() is False
    monkeypatch.setenv("LLM_BASE_URL", "http://ollama:11434/v1")
    assert llm.is_configured() is True
