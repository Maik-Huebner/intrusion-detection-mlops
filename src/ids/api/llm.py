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
"""

import os
import re
import time

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = (
    "Du bist Assistent in einem Security Operations Center (SOC). "
    "Zwei Machine-Learning-Modelle haben eine Netzwerkverbindung (Flow) bewertet. "
    "Schreibe für einen Analysten eine kurze Notiz auf Deutsch, höchstens drei Sätze: "
    "1. was erkannt wurde, 2. welche Merkmale auffallen, 3. was der Analyst als Nächstes prüfen sollte. "
    "Nenne den Angriffstyp genau so, wie er im Text steht. Nenne keine andere Angriffsart. "
    "Erfinde keine IP-Adressen, Hostnamen, CVE-Nummern oder Messwerte; nutze nur die Werte aus dem Text. "
    "Steht im Text eine Warnung zum Drift, übernimm sie mit dem Wort 'Drift'."
)

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
        f"Angriffstyp-Modell: {ctx['attack_type']} (Familie {ctx['family']}, "
        f"Sicherheit {ctx['type_confidence']:.0%}).",
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


def check_rules(text: str, ctx: dict) -> dict[str, bool]:
    """Rules every note must pass (same idea as the LLM evaluation in the course, day 18)."""
    lower = text.lower()
    others = [f for f in FAMILIES if f != ctx["family"] and f.lower() not in ctx["attack_type"].lower()]
    return {
        "names_attack_type": ctx["attack_type"].lower() in lower or ctx["family"].lower() in lower,
        "no_other_attack_family": not any(re.search(rf"\b{re.escape(f.lower())}\b", lower) for f in others),
        "no_invented_identifiers": not (_IP.search(text) or _CVE.search(text) or _URL.search(text)),
        "keeps_drift_warning": (not ctx["drift_warning"]) or "drift" in lower,
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
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(ctx)},
        ],
        temperature=0,  # as reproducible as an LLM gets: same flow, same note
        max_tokens=220,
    )
    return {
        "text": (answer.choices[0].message.content or "").strip(),
        "llm_model": s["model"],
        "tokens": answer.usage.total_tokens if answer.usage else None,
        "seconds": round(time.perf_counter() - start, 2),
    }
