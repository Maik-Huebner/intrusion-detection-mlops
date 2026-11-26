# Sicherheit

Stand der Sicherheitsanalyse: 26.11.2026. Geprüft wurden der Code, die Abhängigkeiten, das Docker-Image,
die Git-Historie, die CI/CD-Pipeline und der Betrieb auf dem Server. Die automatischen Prüfungen laufen
bei jedem Push in CI weiter (Job `security` und Image-Scan im Job `image`).

Eine Schwachstelle bitte nicht als öffentliches Issue melden, sondern über
[GitHub Security Advisories](https://github.com/Maik-Huebner/intrusion-detection-mlops/security/advisories/new).

## Bedrohungsmodell in einem Satz

Die API ist öffentlich erreichbar: Jeder kann Flows schicken, Notizen anfordern und das Dashboard
ansehen. Schützen müssen wir den **Claude-API-Key** (Kosten), den **Server** (er betreibt auch andere
Seiten), die **Lieferkette** (Abhängigkeiten, Actions, Images) und die **Verfügbarkeit** der API.

## Befunde und Maßnahmen

| # | Befund | Risiko | Maßnahme |
|---|---|---|---|
| 1 | Ein Flow mit `NaN` oder `Infinity` führte zu **HTTP 500**: FastAPI wollte den ungültigen Wert in der Fehlermeldung zurückschicken, JSON kann ihn nicht darstellen. | mittel (Fehlerbild, Log-Rauschen) | `allow_inf_nan=False` im Flow-Schema; eigene 422-Antwort **ohne Echo der Eingabe**; Test `test_nan_and_infinity_are_rejected` |
| 2 | `/explain` ruft ein kostenpflichtiges LLM auf; ein öffentlicher Endpunkt könnte beliebig viele Aufrufe auslösen. | hoch (Kosten) | Budget in der API: höchstens 10 Claude-Notizen pro Minute und 300 pro Tag (`LLM_MAX_PER_MINUTE/DAY`), darüber Vorlage mit `reason=budget`; dazu nginx-Ratenlimit (20 Anfragen/s je IP); Ausgabenlimit in der Anthropic Console |
| 3 | Grafana startet mit `admin/admin`. Bei anonymem Lesezugriff im Internet wäre der Admin-Login offen. | hoch | Produktion: Login-Formular und Basic Auth abgeschaltet, keine Registrierung, zufälliges Admin-Passwort (auf dem Server erzeugt, verlässt ihn nie) |
| 4 | `/metrics` verrät Interna (Modellversion, Drift-Merkmale, Fehlerzahlen). | niedrig | Proxy beantwortet `/metrics` von außen mit 404; Prometheus liest intern |
| 5 | Kommandozeilen-Werkzeuge öffnen URLs aus Umgebungsvariablen mit `urllib` – das öffnet auch `file:`-URLs. | niedrig | ein gemeinsames `ids.web.urlopen`, das nur http/https zulässt |
| 6 | Deployment per SSH: ein gewöhnlicher Schlüssel in GitHub wäre eine Shell auf dem Server. | hoch | eigener ed25519-Schlüssel mit **forced command** und `restrict`: er kann nur `ids-deploy` ausführen, keine Shell, keine Weiterleitung (getestet). `ids-deploy` akzeptiert nur `deploy <40-stelliger Commit>` und nur Commits auf `main`; der Host-Key des Servers ist im Workflow fest hinterlegt |
| 7 | Actions über Tags (`@v7`) können nachträglich auf anderen Code zeigen (Lieferkettenangriff). | mittel | alle Actions auf Commit-SHAs fixiert; Dependabot hält sie aktuell |
| 8 | Bekannte Schwachstellen in Abhängigkeiten | mittel | `pip-audit` über alle Pakete aus `uv.lock` in CI; Trivy-Scan des Images blockiert das Deployment bei behebbaren kritischen Befunden |
| 9 | Container mit vollen Rechten könnten bei einer Lücke den Server gefährden. | mittel | alle Produktions-Container: Nicht-Root, schreibgeschütztes Dateisystem, keine Linux-Capabilities, `no-new-privileges`, Speicher-, CPU- und Prozesslimits; Prometheus und Grafana in einem Netz **ohne Internetzugang** |
| 10 | Prompt-Injection und unsichere LLM-Ausgabe | hoch, ohne Gegenmaßnahmen | siehe nächster Abschnitt |

## KI-Sicherheit (OWASP Top 10 für LLM-Anwendungen 2025)

Die LLM-Notiz ist der einzige Teil, in dem ein Sprachmodell Text erzeugt. Jeder Punkt der
[OWASP Top 10 für LLM-Anwendungen](https://genai.owasp.org/llm-top-10/) wurde geprüft; „Test“ nennt den
automatischen Nachweis in `tests/`.

| OWASP | Risiko hier | Schutz | Test |
|---|---|---|---|
| **LLM01 Prompt Injection** | Ein Angreifer schickt Anweisungen statt Messwerten. | **Durch den Aufbau ausgeschlossen:** Die API nimmt nur 83 Zahlen an (`strict`, `extra="forbid"`, keine `NaN`). Der Prompt enthält nur Ergebnisse der eigenen Modelle; Typ, Familie, Merkmalsnamen und Zahlen werden vor jedem Aufruf gegen Allowlists geprüft (`validate_context`), sonst kein LLM-Aufruf. Kein RAG, keine Webseiten, keine Dateien – keine indirekte Injection. Der Systemprompt sagt zusätzlich: Eingaben sind Daten, nie Anweisungen. | `test_prompt_injection_through_the_request_is_impossible`, `test_prompt_context_must_come_from_the_models` |
| **LLM02 Offenlegung sensibler Daten** | Key oder interne Daten in Prompt oder Antwort | Im Prompt stehen keine Geheimnisse und keine personenbezogenen Daten (der Datensatz enthält keine; IPs werden schon in der Pipeline entfernt). Der Key liegt nur in `secrets.env`; Fehler werden ohne Inhalt geloggt. | `test_claude_note_is_cleaned_and_counted` |
| **LLM03 Lieferkette** | manipuliertes SDK oder Modell | Anthropic-SDK fest versioniert in `uv.lock`, pip-audit, Dependabot; Modell-ID fest im Code | CI-Job `security` |
| **LLM04 Daten- und Modellvergiftung** | manipulierte Trainingsdaten | Das LLM wird nicht trainiert. Die eigenen Modelle lernen nur aus Rohdaten mit SHA-256-Prüfung und Validierungsstufe. | `tests/test_validate.py`, CI-Pipeline |
| **LLM05 Unsichere Verarbeitung der Ausgabe** | HTML/JavaScript oder Links in der Notiz landen in einer Oberfläche | Ausgabe gilt als nicht vertrauenswürdig: Steuer- und unsichtbare Unicode-Zeichen (z. B. Richtungswechsel) werden entfernt, die Regel `no_markup` verwirft HTML, Markdown, Links und `javascript:`; `no_invented_identifiers` verwirft IPs, CVEs und URLs. Die Startseite setzt Text nur per `textContent` und sendet eine strenge Content-Security-Policy. | `test_markup_and_links_in_notes_are_rejected`, `test_invisible_and_control_characters_are_removed`, `test_start_page_has_examples_and_no_external_resources` |
| **LLM06 Übermäßige Handlungsfreiheit** | LLM löst Aktionen aus | Das LLM hat **keine Werkzeuge** und keine Rechte. Ob ein Flow ein Angriff ist, entscheiden die beiden geprüften Modelle; das LLM formuliert nur. | Aufbau (kein `tools`-Parameter) |
| **LLM07 Preisgabe des Systemprompts** | Angreifer liest den Prompt aus | Der Prompt enthält nichts Geheimes und ist ohnehin öffentlich im Repository; ohne Text-Eingabe gibt es keinen Weg, ihn abzufragen. | – |
| **LLM08 Schwächen bei Vektoren/Embeddings** | – | nicht zutreffend: kein RAG, keine Vektordatenbank | – |
| **LLM09 Falschinformation** | erfundene Fakten, falscher Angriffstyp | Sieben Regeln je Notiz (Typ nennen, keine andere Familie, keine erfundenen Kennungen, Drift genau dann, wenn gewarnt …), sonst Vorlage. Der Drift-Monitor warnt in der Notiz, wenn der Typ falsch sein kann. Gemessen in MLflow: 26 von 26 Notizen bestehen (Claude, Prompt v3, Regeln r3). | `tests/test_llm.py`, `ids.evaluate_llm` |
| **LLM10 Unbegrenzter Verbrauch** | Kosten- oder Last-Angriff über `/explain` | Budget 10 Notizen/Minute und 300/Tag, `max_tokens` 2048, Timeout 60 s, nginx-Ratenlimit 20/s je IP, 12 MB je Anfrage, Ausgabenlimit in der Anthropic Console | `test_explain_over_budget_uses_the_template`, `test_budget_per_minute_and_per_day` |

Dazu: Lehnt Claude eine Anfrage ab (`stop_reason: refusal`) oder schneidet sie ab, kommt die Vorlage;
bei Opus 5.5 antwortet serverseitig zuerst ein Fallback-Modell (`fallbacks: "default"`).

**Grenze:** Absolute Sicherheit gibt es nicht. Die Angriffsfläche für Prompt-Injection ist hier aber
nicht nur „gefiltert“, sondern fehlt: Es gibt keinen Weg, auf dem Text eines Nutzers in den Prompt kommt.
Wer die API um Freitext erweitert (z. B. Analysten-Kommentare), muss diesen Abschnitt neu bewerten.

## Was automatisch geprüft wird

| Prüfung | Werkzeug | Wo |
|---|---|---|
| Bekannte Schwachstellen in Python-Paketen | `pip-audit` (alle Gruppen aus `uv.lock`) | CI, Job `security` |
| Unsichere Muster im Code | Ruff-Regeln `S` (flake8-bandit) | CI, Job `lint` |
| Geheimnisse in der Git-Historie | `gitleaks` (gesamte Historie) | CI, Job `security` |
| Schwachstellen im Image | Trivy (kritisch und behebbar = Abbruch) | CI, Job `image`, vor dem Push |
| Laufendes Image antwortet richtig | Smoke-Test (`/health`, Revision in `/model`) | CI, vor dem Push und nach dem Deployment über das Internet |
| Veraltete Abhängigkeiten | Dependabot (uv, Actions, Docker), wöchentlich | GitHub |

Ergebnis am 26.11.2026: keine Geheimnisse in der Git-Historie, keine Befunde der
Ruff-Sicherheitsregeln (nach den Korrekturen oben), im Image **keine behebbare Schwachstelle der Stufe
hoch oder kritisch** (Trivy, Debian- und Python-Pakete), ein bekannter Befund in den
Entwicklungsabhängigkeiten (siehe unten). Trivys Secret-Scanner meldet zwei Treffer im Image – beides
Beispiel-JSON in Docstrings des Anthropic-SDK, keine echten Schlüssel; im Image prüft Trivy deshalb nur
Schwachstellen, Geheimnisse prüft gitleaks im Repository.

## Geheimnisse

| Geheimnis | Wo es liegt | Nie |
|---|---|---|
| `ANTHROPIC_API_KEY` | lokal `secrets.env` (in `.gitignore` und `.dockerignore`), auf dem Server `~/.config/ids/secrets.env` mit Rechten 600 | in Git, im Image, in GitHub, in Logs |
| Deploy-Schlüssel | GitHub-Secret `DEPLOY_SSH_KEY`; öffentlicher Teil mit forced command auf dem Server | als Schlüssel mit Shell-Rechten |
| Grafana-Admin-Passwort | nur auf dem Server, beim ersten Deployment zufällig erzeugt | im Repository |
| GHCR-Zugang | kurzlebiges `GITHUB_TOKEN` des Workflows | als persönlicher Token |

## Akzeptierte Risiken

- **`diskcache` 5.6.3 (CVE-2025-69872, PYSEC-2026-2447):** Der Cache deserialisiert mit pickle. Es gibt
  keine behobene Version. Das Paket kommt nur über DVC in die Entwicklungsumgebung (lokaler Cache
  unter `.dvc/tmp`), nicht ins API-Image. Ausnutzbar nur mit Schreibrechten auf dieses Verzeichnis.
  In CI ausdrücklich ignoriert, sonst würde jede Prüfung scheitern.
- **Modelle per joblib/pickle:** Die API lädt ihr Modell aus dem Image, das CI selbst trainiert und
  gebaut hat, oder aus der eigenen MLflow-Registry (skops mit festgelegten vertrauenswürdigen Typen).
  Fremde Modelldateien dürfen nie geladen werden.
- **`/predict` ohne Authentifizierung:** gewollt für die Demo. Für einen echten Betrieb: API-Keys oder
  mTLS je Sensor, dazu ein Ratenlimit je Client.
- **MLflow ohne Authentifizierung:** läuft nur lokal (127.0.0.1), nie auf dem Server.
- **sslip.io:** Der Name wird von einem fremden DNS-Dienst aufgelöst. Für einen echten Betrieb gehört
  die API unter eine eigene Domain; dafür reicht es, `~/.config/ids/domain` und den nginx-vhost zu ändern.
