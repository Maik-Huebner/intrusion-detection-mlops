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


def test_provider_follows_the_configuration(monkeypatch):
    for var in ("LLM_BASE_URL", "LLM_PROVIDER", "ANTHROPIC_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    assert llm.is_configured() is False
    monkeypatch.setenv("LLM_BASE_URL", "http://ollama:11434/v1")
    assert llm.settings()["provider"] == "openai" and llm.is_configured()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    assert llm.settings()["provider"] == "anthropic" and llm.settings()["model"] == "claude-opus-5-5"
    monkeypatch.setenv("LLM_PROVIDER", "off")
    assert llm.is_configured() is False
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert llm.is_configured() is False  # Claude without a key: template notes


def test_uncertain_type_must_be_called_unclear():
    ctx = CTX | {"uncertain": True, "attack_type": "unklarer Angriffstyp", "family": "unklar"}
    assert "unklar" in llm.build_prompt(ctx) and "SSH-Patator" not in llm.build_prompt(ctx)
    assert llm.check_rules("Ein Angriff wurde erkannt, der Typ ist unklar. Quelle prüfen.", ctx)[
        "names_attack_type"
    ]
    assert not llm.check_rules("Ein uncertain-Angriff der Familie uncertain.", ctx)["names_attack_type"]


def test_budget_per_minute_and_per_day():
    from datetime import date

    budget = llm.Budget(per_minute=2, per_day=3)
    day = date(2026, 11, 26)
    assert budget.allow(0, day) and budget.allow(1, day)
    assert not budget.allow(2, day)  # third call within a minute
    assert budget.allow(61, day)  # a minute later
    assert not budget.allow(200, day)  # daily limit reached
    assert budget.allow(300, date(2026, 11, 27))  # new day


class _Block:
    def __init__(self, type_, text=""):
        self.type, self.text = type_, text


class _FakeMessages:
    def __init__(self, stop_reason, calls):
        self.stop_reason, self.calls = stop_reason, calls

    def create(self, **kwargs):
        self.calls.append(kwargs)

        class Usage:
            input_tokens, output_tokens = 700, 120

        class Answer:
            stop_reason = self.stop_reason
            model = kwargs["model"]
            usage = Usage()
            content = [_Block("thinking"), _Block("text", "Hier ist die Notiz: " + GOOD)]

        return Answer()


def _fake_anthropic(monkeypatch, stop_reason="end_turn"):
    import anthropic

    calls = []

    class FakeClient:
        def __init__(self, **kwargs):
            calls.append({"client": kwargs})
            self.beta = type("Beta", (), {"messages": _FakeMessages(stop_reason, calls)})()

    monkeypatch.setattr(anthropic, "Anthropic", FakeClient)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    for var in ("LLM_PROVIDER", "LLM_MODEL", "LLM_EFFORT", "ANTHROPIC_WORKSPACE_ID"):
        monkeypatch.delenv(var, raising=False)
    return calls


def test_claude_note_is_cleaned_and_counted(monkeypatch):
    calls = _fake_anthropic(monkeypatch)
    answer = llm.generate(CTX)
    assert answer["text"] == GOOD and answer["tokens"] == 820 and answer["llm_model"] == "claude-opus-5-5"
    assert calls[0]["client"]["default_headers"] is None
    request = calls[1]
    assert request["output_config"] == {"effort": "low"} and request["fallbacks"] == "default"
    assert "temperature" not in request  # removed from the current API
    assert "SSH-Patator" in request["messages"][0]["content"]


def test_claude_refusal_falls_back(monkeypatch):
    _fake_anthropic(monkeypatch, stop_reason="refusal")
    try:
        llm.generate(CTX)
    except llm.NoNoteError as exc:
        assert str(exc) == "refusal"
    else:
        raise AssertionError("a refusal must not become a note")


def test_workspace_header_for_keys_without_workspace(monkeypatch):
    calls = _fake_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", "wrkspc_test")
    llm.generate(CTX)
    assert calls[0]["client"]["default_headers"] == {"anthropic-workspace-id": "wrkspc_test"}
