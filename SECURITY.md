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
| 10 | Prompt-Injection über die Notiz | niedrig | Der Prompt enthält nur Zahlen und Ergebnisse der eigenen Modelle, keinen Text aus der Anfrage. Die Ausgabe prüfen sechs Regeln (u. a. keine erfundenen IPs, CVEs oder URLs); Fehler werden ohne Inhalt geloggt |

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
