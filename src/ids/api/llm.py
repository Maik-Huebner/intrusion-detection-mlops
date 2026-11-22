"""Analyst note: an LLM turns the models' findings into a short triage note in German.

The LLM does **not** decide what the attack is - the detector and the attack type model do. It only
gets their results (type, family, probabilities), the features that lie furthest outside normal
traffic and the state of the drift monitor, and writes them up for a SOC analyst. Every note is
checked against rules; a note that breaks one, a timeout or an unreachable LLM falls back to a
template. The API never fails because of the LLM.

Configuration (OpenAI-compatible endpoint, e.g. Ollama in the compose stack):

* ``LLM_BASE_URL``  e.g. ``http://ollama:11434/v1``; unset = template notes only
* ``LLM_MODEL``     default ``llama3.2:3b``
* ``LLM_API_KEY``   Ollama ignores it, the openai package requires one (default ``ollama``)
* ``LLM_TIMEOUT``   seconds, default 60
* ``LLM_PROMPT_VERSION`` ``v2`` (default) or ``v1``, to compare prompts in the evaluation

Prompt history (measured with ``ids.evaluate_llm``, rules r2):

* v1: every note started with "Hier ist die Notiz ..." in quotes, and llama3.2:3b mentioned "Drift"
  even without a warning - it echoed the word from the system prompt.
* v2: the drift instruction is only in the prompt when there is a warning; no preamble, no quotes;
  a deterministic cleanup removes a preamble the model writes anyway.
"""

import os
import re
import time

RULES_VERSION = "r2"

SYSTEM_PROMPT_V1 = (
    "Du bist Assistent in einem Security Operations Center (SOC). "
    "Zwei Machine-Learning-Modelle haben eine Netzwerkverbindung (Flow) bewertet. "
    "Schreibe für einen Analysten eine kurze Notiz auf Deutsch, höchstens drei Sätze: "
    "1. was erkannt wurde, 2. welche Merkmale auffallen, 3. was der Analyst als Nächstes prüfen sollte. "
    "Nenne den Angriffstyp genau so, wie er im Text steht. Nenne keine andere Angriffsart. "
    "Erfinde keine IP-Adressen, Hostnamen, CVE-Nummern oder Messwerte; nutze nur die Werte aus dem Text. "
    "Steht im Text eine Warnung zum Drift, übernimm sie mit dem Wort 'Drift'."
)

_V2_BASE = (
    "Du bist Assistent in einem Security Operations Center (SOC). "
    "Zwei Machine-Learning-Modelle haben eine Netzwerkverbindung (Flow) bewertet. "
    "Schreibe für einen Analysten eine Notiz auf Deutsch in genau drei kurzen Sätzen: "
    "1. was erkannt wurde, 2. welche zwei Merkmale am meisten auffallen, mit Wert und normalem Bereich, "
    "3. was der Analyst als Nächstes prüfen sollte. "
    "Nenne den Angriffstyp genau so, wie er im Text steht, und keine andere Angriffsart. "
    "Erfinde keine IP-Adressen, Hostnamen, CVE-Nummern oder Messwerte. "
    "Antworte nur mit den drei Sätzen: keine Einleitung, keine Überschrift, keine Anführungszeichen."
)
_V2_DRIFT = (
    " Der Text enthält eine Warnung des Drift-Monitors: Beginne den dritten Satz mit 'Achtung, Drift:' "
    "und schreibe, dass die Zuordnung falsch sein kann."
)


def prompt_version() -> str:
    return os.getenv("LLM_PROMPT_VERSION", "v2")


def system_prompt(ctx: dict) -> str:
    if prompt_version() == "v1":
        return SYSTEM_PROMPT_V1
    return _V2_BASE + (_V2_DRIFT if ctx["drift_warning"] else "")


_PREAMBLE = re.compile(r"^\s*(hier ist|hier die|here is|notiz)[^\n]*:\s*", re.IGNORECASE)
_QUOTES = "\"'„“”«»"


def clean(text: str) -> str:
    """Remove a preamble line and surrounding quotes - code, not the prompt, guarantees the format."""
    return _PREAMBLE.sub("", text.strip()).strip().strip(_QUOTES).strip()


# Attack families a note may mention; anything but the predicted one is a hallucination.
FAMILIES = ["Brute Force", "DoS", "DDoS", "Heartbleed", "Web Attack", "Infiltration", "Botnet", "PortScan"]
MAX_WORDS = 90
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
_URL = re.compile(r"https?://|www\.", re.IGNORECASE)


def settings() -> dict:
    """Read on every call, so tests and deployments can change it without a restart of Python."""
    return {
        "base_url": os.getenv("LLM_BASE_URL", ""),
        "model": os.getenv("LLM_MODEL", "llama3.2:3b"),
        "api_key": os.getenv("LLM_API_KEY", "ollama"),
        "timeout": float(os.getenv("LLM_TIMEOUT", "60")),
    }


def is_configured() -> bool:
    return bool(settings()["base_url"])


def _fmt(value: float) -> str:
    return f"{value:,.0f}".replace(",", ".") if abs(value) >= 100 else f"{value:.3g}".replace(".", ",")


def build_prompt(ctx: dict) -> str:
    lines = [
        f"Detektor: Angriff mit Wahrscheinlichkeit {ctx['attack_probability']:.0%}.",
        (
            f"Angriffstyp-Modell: kein bekannter Angriffstyp ist sicher genug (höchstens "
            f"{ctx['type_confidence']:.0%}) - der Angriffstyp ist unklar."
            if ctx.get("uncertain")
            else f"Angriffstyp-Modell: {ctx['attack_type']} (Familie {ctx['family']}, "
            f"Sicherheit {ctx['type_confidence']:.0%})."
        ),
        f"Zielport {int(ctx['dst_port'])}, Protokoll {int(ctx['protocol'])}.",
        "Auffälligste Merkmale im Vergleich zu normalem Verkehr (normal = 10-90 % der harmlosen Flows):",
    ]
    lines += [
        f"- {f['feature']}: {_fmt(f['value'])} (normal {_fmt(f['normal_low'])} bis {_fmt(f['normal_high'])})"
        for f in ctx["unusual_features"]
    ] or ["- keine Merkmale außerhalb des normalen Bereichs"]
    if ctx["drift_warning"]:
        lines.append(
            "Warnung: Der Drift-Monitor meldet gerade ungewöhnlichen Verkehr. Neue Angriffsarten ordnet das "
            "Angriffstyp-Modell trotzdem einer bekannten Art zu - die Zuordnung kann falsch sein."
        )
    lines.append("Schreibe die Notiz.")
    return "\n".join(lines)


def _names(ctx: dict) -> list[str]:
    """How a note may refer to the attack: its type or family - or, if uncertain, say so."""
    if ctx.get("uncertain"):
        return ["unklar", "unbekannt"]
    return [ctx["attack_type"].lower(), ctx["family"].lower()]


def check_rules(text: str, ctx: dict) -> dict[str, bool]:
    """Rules every note must pass (version ``RULES_VERSION``, same idea as the course's day 18)."""
    lower = text.lower()
    stripped = text.strip()
    others = [f for f in FAMILIES if f != ctx["family"] and f.lower() not in ctx["attack_type"].lower()]
    return {
        "names_attack_type": any(n in lower for n in _names(ctx)),
        "no_other_attack_family": not any(re.search(rf"\b{re.escape(f.lower())}\b", lower) for f in others),
        "no_invented_identifiers": not (_IP.search(text) or _CVE.search(text) or _URL.search(text)),
        "drift_only_when_warned": ("drift" in lower) == ctx["drift_warning"],
        "no_preamble": not (_PREAMBLE.match(stripped) or stripped[:1] in _QUOTES),
        "short": len(text.split()) <= MAX_WORDS,
    }


def fallback_note(ctx: dict) -> str:
    features = ", ".join(f["feature"] for f in ctx["unusual_features"][:3]) or "keine auffälligen Merkmale"
    note = (
        f"Alarm: {ctx['attack_type']} (Familie {ctx['family']}), "
        f"Wahrscheinlichkeit {ctx['attack_probability']:.0%}, "
        f"Zielport {int(ctx['dst_port'])}. Auffällig: {features}. "
        "Nächster Schritt: Quelle und weitere Verbindungen im selben Zeitraum prüfen."
    )
    if ctx["drift_warning"]:
        note += " Achtung: Der Drift-Monitor meldet ungewöhnlichen Verkehr, die Zuordnung kann falsch sein."
    return note


def no_alarm_note(probability: float) -> str:
    return (
        "Kein Alarm: Der Detektor stuft den Flow als harmlos ein "
        f"(Angriffswahrscheinlichkeit {probability:.0%})."
    )


def generate(ctx: dict) -> dict:
    """Ask the LLM. Raises on timeouts and connection errors - the caller falls back."""
    from openai import OpenAI  # api group; imported here so the rest of the API works without it

    s = settings()
    client = OpenAI(base_url=s["base_url"], api_key=s["api_key"], timeout=s["timeout"], max_retries=0)
    start = time.perf_counter()
    answer = client.chat.completions.create(
        model=s["model"],
        messages=[
            {"role": "system", "content": system_prompt(ctx)},
            {"role": "user", "content": build_prompt(ctx)},
        ],
        temperature=0,  # as reproducible as an LLM gets: same flow, same note
        max_tokens=220,
    )
    text = (answer.choices[0].message.content or "").strip()
    return {
        "text": clean(text) if prompt_version() != "v1" else text,
        "llm_model": s["model"],
        "prompt_version": prompt_version(),
        "tokens": answer.usage.total_tokens if answer.usage else None,
        "seconds": round(time.perf_counter() - start, 2),
    }
