# Intrusion Detection MLOps

[![CI](https://github.com/Maik-Huebner/intrusion-detection-mlops/actions/workflows/ci.yml/badge.svg)](https://github.com/Maik-Huebner/intrusion-detection-mlops/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20|%203.13%20|%203.14-blue)
![DVC](https://img.shields.io/badge/data-DVC-945dd6)
![MLflow](https://img.shields.io/badge/registry-MLflow-0194e2)
![FastAPI](https://img.shields.io/badge/serving-FastAPI-009688)
![Prometheus](https://img.shields.io/badge/monitoring-Prometheus%20%2B%20Grafana-e6522c)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> **TL;DR (English).** An end-to-end MLOps system that detects network attacks in flow data
> (corrected CIC-IDS2017, 2.1 M flows) – and notices when it goes stale. A model that is perfect on
> Monday–Wednesday catches **0 %** of Thursday's new attacks and stays silent: no alarms, hardly any uncertainty.
> A label-free drift monitor on the traffic the model lets through fires anyway. Retraining with
> Thursday as a DVC experiment, champion/challenger promotion in the MLflow registry and a rollout
> without rebuilding the image bring Friday's never-seen attacks from **37 %** to **99 %**.
> Everything runs locally with one `docker compose` stack (MLflow, FastAPI, Prometheus, Grafana) and is
> rebuilt from the raw data and checked for byte-identical results by CI on every push.

Ein Machine-Learning-Modell erkennt im Netzwerkverkehr, ob eine Verbindung normal ist oder zu einem
Angriff gehört (DoS, Brute Force, PortScan, Botnet, Web-Angriffe …). Im Mittelpunkt steht aber nicht
das Modell, sondern der **Kreislauf drumherum**: Daten versionieren und prüfen, reproduzierbar
trainieren, nur geprüfte Modelle ausrollen, im Betrieb merken, dass das Modell veraltet, neu trainieren
und das neue Modell kontrolliert ausrollen.

**Inhalt:** [Die Geschichte in drei Bildern](#die-geschichte-in-drei-bildern) ·
[Der MLOps-Kreislauf](#der-mlops-kreislauf) · [Monitoring ohne Labels](#monitoring-ohne-labels) ·
[Architektur](#architektur) · [Datensatz](#der-datensatz-und-warum-die-korrigierte-fassung) ·
[Schnellstart](#schnellstart) · [Live-Demo](#live-demo-in-vier-befehlen) ·
[Erkenntnisse](#erkenntnisse-aus-dem-projekt) · [Grenzen](#grenzen-und-nächste-schritte)

## Die Geschichte in drei Bildern

### 1. Offline perfekt, im Einsatz blind

Ein Modell, trainiert mit dem Verkehr von **Montag bis Mittwoch**, trifft auf **Donnerstag und Freitag**:

![Erkennungsrate je Angriffsart](reports/detection_by_attack.svg)

| | Erkennungsrate | Fehlalarme |
|---|---:|---:|
| Bekannte Angriffsarten (Testdaten Mo–Mi) | **100,0 %** (35.714 von 35.715) | 0 |
| Donnerstag (Infiltration, Web-Angriffe) | **0,0 %** (0 von 71.902) | 2 von 290.018 |
| Freitag (PortScan, DDoS, Botnet) | **37,3 %** – fast nur DDoS | 1 von 292.506 |

Das ist **Concept Drift**: Angreifer benutzen neue Methoden, und das Modell hat sie nie gesehen.
Gefährlich daran ist nicht die schlechte Zahl, sondern dass sie im Betrieb **niemand sieht**. Die echten
Labels kennt ein SOC erst Tage später, wenn Analysten die Vorfälle bestätigt haben.

### 2. Das Modell schweigt, die Daten nicht

Am Donnerstag gibt das Modell **null Treffer** aus, und es ist sich dabei fast völlig sicher: Nur 8 von
361.920 Vorhersagen liegen zwischen 10 % und 90 %. Wer nur auf die Ausgabe des Modells schaut, sieht einen ruhigen
Tag. Der Drift-Monitor vergleicht deshalb die **Eingabedaten**, genauer die Flows, die das Modell als
harmlos durchlässt, mit dem normalen Trainingsverkehr. Er braucht dafür keine Labels:

![Drift-Monitor je Tag](reports/drift_by_day.svg)

| Verkehr, den das Modell durchlässt | Merkmale mit Drift (PSI > 0,2) | Alarm |
|---|---:|:---:|
| Testdaten Mo–Mi | 0 von 83 (0 %) | – |
| Donnerstag | 24 von 83 (29 %) | **ja** |
| Freitag | 39 von 83 (47 %) | **ja** |
| Freitag, nach dem Retraining (Modell Mo–Do) | 0 von 83 (0 %) | – |

### 3. Der Kreislauf schließt sich – live gemessen

Die Live-Demo spielt echten Verkehr gegen die laufende API ab. Prometheus misst, Grafana zeigt an:

![Live-Demo, gemessen von Prometheus](docs/images/live_demo.png)

1. **Mittwoch** mit Modell v3 (Mo–Mi): DoS-Angriffe werden zu 100 % erkannt, kein Drift.
2. **Donnerstag:** 0 von 6.124 Angriffen erkannt, alles „grün“. Der Drift-Monitor springt auf 30 %,
   Prometheus löst den Alarm `IdsDataDrift` aus.
3. **Retraining** mit den gelabelten Donnerstagsdaten (DVC-Experiment), **Champion/Challenger** in der
   MLflow-Registry: v4 schlägt v3 auf den aktuellen Daten (F1 0,9986 gegen 0,8963) und wird `@champion`.
   **Rollout** durch Neustart der API, ohne neues Image.
4. **Freitag** mit v4, Angriffe, die auch v4 nie gesehen hat: **99,1 %** erkannt (vorher 37,3 %),
   PortScan 99,2 %, DDoS 99,9 %, Fehlalarmrate 0,19 %.

| Grafana im Moment des Alarms | Prometheus-Alarm |
|---|---|
| ![Grafana-Dashboard bei Drift](docs/images/grafana_drift.jpg) | ![Prometheus-Alarm IdsDataDrift](docs/images/prometheus_alert.png) |

## Warum MLOps gerade in der Cybersecurity?

Angreifer ändern ständig ihre Methoden. Ein Modell, das heute fast alle Angriffe findet, kann morgen
blind für eine neue Angriffsart sein, ohne dass sich an seinem Code etwas ändert. Ein einmal trainiertes
Modell reicht deshalb nicht. Man braucht ein System, das **merkt**, wenn sich der Verkehr verändert,
neue Daten aufnimmt und prüft, neu trainiert, das neue Modell gegen das alte vergleicht und es nur dann
ausrollt, wenn es wirklich besser ist – mit einem Weg zurück, falls doch etwas schiefgeht.

## Der MLOps-Kreislauf

```mermaid
flowchart LR
    D[Daten<br/>DVC + SHA-256] --> P[Pipeline<br/>dvc repro]
    P --> G{Quality Gate}
    G -->|bestanden| R[MLflow Registry<br/>neue Version]
    R --> C{Champion vs.<br/>Challenger}
    C -->|besser| A["API lädt @champion<br/>(Rollout = Neustart)"]
    A --> M[Monitoring<br/>Prometheus + Grafana]
    M -->|IdsDataDrift| L[Verkehr labeln]
    L -->|dvc exp run| P
    C -.->|nicht besser| A
    A -.->|make rollback| R
```

| Schritt | Befehl | Was passiert |
|---|---|---|
| Trainieren | `make pipeline` | DVC rechnet nur die Stufen neu, deren Eingaben sich geändert haben |
| Registrieren | `make register` | Run mit Parametern, Metriken, Berichten, Daten-Hash und Git-Commit; neue Modellversion; Champion/Challenger-Entscheidung |
| Ausrollen | `make rollout` | API neu starten, sie lädt `models:/ids-detector@champion` samt Drift-Profil |
| Beobachten | Grafana, Prometheus | goldene Signale, Alarmrate, Drift, Modellversion; Alarmregeln |
| Neu trainieren | `make retrain` | DVC-Experiment mit Donnerstag im Training, danach Registrierung und Promotion |
| Zurückrollen | `make rollback V=3` | `@champion` zeigt wieder auf Version 3, die API lädt sie |

Der Champion/Challenger-Vergleich ([`registry.py`](src/ids/registry.py)) misst **beide Modelle auf
denselben, neuesten gelabelten Daten**. Die eigene Testmetrik des alten Champions sagt nach einem Drift
nichts mehr über den heutigen Verkehr aus. Ein Challenger muss zusätzlich das Quality Gate bestehen und
den Champion um mindestens 0,005 F1 schlagen.

## Monitoring ohne Labels

### Warum nicht einfach die Alarmrate überwachen?

Weil das Modell bei einer unbekannten Angriffsart **selbstsicher falsch** liegt. Am Donnerstag sinkt die
Alarmrate sogar auf praktisch 0 (2 Fehlalarme) – das sieht aus wie ein ruhiger Tag. Auch die Unsicherheit
bleibt bei praktisch 0 (8 von 361.920 Flows zwischen 10 % und 90 %). Signale aus der Modellausgabe helfen hier nicht.

### Was stattdessen überwacht wird

[`ids/drift.py`](src/ids/drift.py) berechnet für jedes der 83 Merkmale den
**Population Stability Index (PSI)**:

1. Beim Training entsteht ein **Referenzprofil** des normalen Verkehrs: je Merkmal zehn Quantil-Intervalle
   und der Anteil der Trainings-Flows darin. Das Profil gehört zur Modellversion, wird in MLflow mit dem
   Modell gespeichert und mit ihm ausgerollt.
2. Die API sammelt die letzten 1.000 Flows, die das Modell als harmlos durchlässt, und vergleicht ihre
   Verteilung mit dem Profil: `PSI = Σ (neu − ref) · ln(neu / ref)`.
3. Hat mehr als 10 % der Merkmale einen PSI über 0,2, gilt der Verkehr als gedriftet.

**Warum nur die durchgelassenen Flows?** Erkannte Angriffe sind schon Alarme. Gefährlich ist der Angriff,
der für das Modell harmlos aussieht – er verändert, wie „harmloser“ Verkehr aussieht. Normaler Verkehr
bleibt dagegen bei 0 % Drift, egal wie viele bekannte Angriffe gerade laufen. In den Daten geprüft: Der
normale Verkehr von Donnerstag und Freitag zeigt allein **0 % Drift**, auch in jedem 1.000er-Fenster. Der
Alarm kommt also von den Angriffen, nicht von einem anderen Wochentag.

Dieselbe Funktion läuft **offline** in der DVC-Stufe `drift` (Ergebnis: [`reports/drift.json`](reports/drift.json))
und **online** in der API (Metriken `ids_drift_share`, `ids_feature_psi`).

### Metriken und Alarme

| Metrik (`/metrics`) | Bedeutung |
|---|---|
| `ids_http_requests_total`, `ids_http_request_duration_seconds` | goldene Signale: Verkehr, Fehler, Latenz |
| `ids_flows_scored_total{verdict}` | bewertete Flows, harmlos oder Angriff → Alarmrate |
| `ids_attack_probability` | Verteilung der Angriffswahrscheinlichkeit → Unsicherheit |
| `ids_drift_share`, `ids_drift_detected`, `ids_feature_psi{feature}` | Drift-Monitor |
| `ids_model_info{version, source, fallback}` | welche Modellversion gerade ausgeliefert wird |

| Alarm ([`alerts.yml`](monitoring/alerts.yml)) | Bedingung |
|---|---|
| `IdsDataDrift` | Drift im durchgelassenen Verkehr seit 30 s – mögliche neue Angriffsart |
| `IdsApiDown` | Prometheus erreicht die API nicht |
| `IdsModelFallback` | Registry beim Start nicht erreichbar, die API nutzt ihr eingebautes Modell |
| `IdsHighErrorRate` | mehr als 5 % Serverfehler |
| `IdsSlowResponses` | p95-Latenz von `/predict` über 250 ms |

### Evaluation der laufenden API

[`ids.evaluate_api`](src/ids/evaluate_api.py) testet die API so, wie ein Client sie benutzt, und
schreibt das Ergebnis nach MLflow (Experiment `ids-api-evaluation`):

| Prüfung | Ergebnis (Modell v4, lokal auf einem M4 Pro) |
|---|---|
| Qualität über HTTP (20.000 Test-Flows) | Erkennungsrate 99,7 %, Fehlalarmrate 0,0 % |
| Latenz `/predict` | p50 6 ms · p95 41 ms · p99 63 ms |
| Durchsatz `/predict/batch` | 13.600 Flows pro Sekunde |
| Robustheit | 6 von 6 ungültigen Anfragen mit 422 abgelehnt, kein Absturz |

## Architektur

```mermaid
flowchart LR
    subgraph Daten
        SRC[(CIC-IDS2017<br/>korrigiert, 328 MB)] -->|download + SHA-256| RAW[data/raw<br/>DVC-versioniert]
    end
    subgraph "DVC-Pipeline (dvc repro)"
        RAW --> P[prepare] --> V{validate} --> S[split<br/>nach Zeit] --> T[train] --> E[evaluate]
        T --> DR[drift<br/>+ Referenzprofil]
        E --> PL[plots]
        DR --> PL
    end
    subgraph "Docker Compose"
        REG[MLflow<br/>Tracking + Registry] -->|"@champion + Profil"| API[FastAPI<br/>/predict · /drift · /metrics]
        API -->|scrape 5 s| PR[Prometheus<br/>Alarmregeln] --> GR[Grafana]
    end
    T -->|"make register"| REG
    API --> U([SOC / Clients])
    subgraph "GitHub Actions"
        CI[lint → Tests 3.12–3.14 → Pipeline auf echten Daten → Reproduzierbarkeit → Quality Gate]
    end
```

| Baustein | Werkzeug | Was es hier leistet |
|---|---|---|
| Umgebung | **uv** + `uv.lock` | exakt gleiche Paketversionen lokal, in CI und im Docker-Image |
| Daten versionieren | **DVC** | Rohdaten und jeder Zwischenstand haben einen Hash; `dvc.lock` hält fest, welcher Datenstand welches Modell erzeugt hat |
| Datenqualität | `ids.pipeline.validate` | Schema, Wertebereiche, Labels; eine Verletzung stoppt die Pipeline |
| Pipeline & Experimente | **DVC** | 7 Stufen, nur Geändertes wird neu gerechnet; Retraining als `dvc exp run` |
| Tracking & Registry | **MLflow** | Runs mit Lineage (Daten-Hash, Git-Commit); Champion/Challenger, Rollback; Modelle als skops statt pickle |
| Quality Gate | `ids.quality_gate` | Erkennungsrate ≥ 98 %, Fehlalarmrate ≤ 0,5 %, F1 ≥ 0,98 – sonst keine Freigabe |
| Serving | **FastAPI** + **Docker** | Validierung jedes Merkmals, Modell aus der Registry mit Rückfall auf das eingebaute Modell, Nicht-Root-Container |
| Monitoring | **Prometheus** + **Grafana** | goldene Signale, Alarmrate, Drift ohne Labels, fünf Alarmregeln, fertig eingerichtetes Dashboard |
| CI | **GitHub Actions** | Lint, Tests auf drei Python-Versionen, komplette Pipeline auf den echten Daten, Byte-Vergleich der Ergebnisse, Quality Gate |

## Der Datensatz und warum die korrigierte Fassung

[CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Canadian Institute for Cybersecurity) ist
einer der meistgenutzten Benchmarks für Intrusion Detection: fünf Tage Netzwerkverkehr (3.–7. Juli 2017)
mit eingeschleusten Angriffen, aufbereitet als Flows mit über 80 Merkmalen.

Das Original hat **bekannte, schwerwiegende Fehler**: falsch gelabelte Angriffe, Fehler im
Feature-Extraktor CICFlowMeter, fehlerhaft zusammengesetzte Flows. Engelen et al. (2021) zeigen, dass
über 20 % der Flows neu erzeugt oder umgelabelt werden müssen. Viele Paper mit „99,9 % Genauigkeit“
messen deshalb teilweise Artefakte statt Angriffe.

Dieses Projekt nutzt die **korrigierte Fassung von Liu, Engelen et al. (IEEE CNS 2022)**, neu erzeugt aus
den Original-PCAPs:

| Tag | Flows | davon Angriffe | Angriffsarten |
|---|---:|---:|---|
| Montag | 371.516 | 0 | nur normaler Verkehr |
| Dienstag | 321.963 | 6.933 | FTP-Patator, SSH-Patator (Brute Force) |
| Mittwoch | 496.527 | 171.642 | DoS Hulk, GoldenEye, Slowloris, Slowhttptest, Heartbleed |
| Donnerstag | 361.920 | 71.902 | Infiltration (mit Portscan aus dem Netz heraus), Web-Angriffe (Brute Force, XSS, SQL Injection) |
| Freitag | 547.452 | 254.946 | PortScan, DDoS, Botnet |

**Bewusste Entscheidungen in der Datenaufbereitung** (Details in [`prepare.py`](src/ids/pipeline/prepare.py)):

1. **„Attempted“-Flows werden normal.** 11.979 Flows gehören zu einem Angriffsskript, enthalten aber
   nichts Bösartiges (z. B. antwortet das Ziel nicht). Die Autoren empfehlen, sie als BENIGN zu werten.
2. **IP-Adressen, Ports der Quelle, Flow-ID und Zeitstempel fliegen raus.** Sonst lernt das Modell
   „172.16.0.1 greift an“ statt „so sieht ein Angriff aus“. Im echten Netz nützt das nichts.
3. **16-Bit-Überlauf in CICFlowMeter.** Die Validierung schlug beim ersten Lauf an: 593 Flows haben eine
   negative Header-Länge, alle zwischen −32.768 und 32.767. Lange Flows laufen in einem 16-Bit-Zähler über.
   Der echte Wert ist nicht rekonstruierbar, die Zeilen (0,03 %) werden entfernt.
4. **Duplikate vor dem Split entfernen** (82.303 Flows). Sonst steht dieselbe Verbindung in Training und
   Test, und das Ergebnis sieht besser aus, als es ist.
5. **Split nach Zeit, nicht zufällig.** Ein Modell im Einsatz kennt nur die Vergangenheit.

## Schnellstart

Voraussetzungen: [uv](https://docs.astral.sh/uv/), Docker, ca. 6 GB freier Speicher.

```bash
git clone https://github.com/Maik-Huebner/intrusion-detection-mlops.git
cd intrusion-detection-mlops
uv sync                              # Umgebung exakt nach uv.lock
make data                            # 328 MB, mit SHA-256-Prüfung
make pipeline                        # komplette Pipeline, ca. 1 Minute auf einem M4 Pro
uv run dvc metrics show              # Ergebnisse
make check                           # Lint und 68 Tests
```

### Den Stack starten

```bash
make stack                           # MLflow, API, Prometheus, Grafana
make register                        # Modell (Mo–Mi) in die Registry, wird @champion
make rollout                         # API lädt den Champion
```

| Dienst | Adresse |
|---|---|
| API mit interaktiver Doku | http://localhost:8000/docs |
| MLflow (Runs, Registry) | http://localhost:5050 |
| Prometheus (Alarme) | http://localhost:9090/alerts |
| Grafana (Dashboard) | http://localhost:3000 (Port über `GRAFANA_PORT` in `local.env`, hier 3001) |

| Endpunkt | Zweck |
|---|---|
| `GET /health` | läuft die API? (auch Docker-Healthcheck) |
| `GET /model` | Modellversion, Quelle, Schwelle, Rückfall ja/nein, Drift-Monitoring an/aus |
| `POST /predict` | einen Flow bewerten (83 Merkmale, jedes mit Wertebereich geprüft) |
| `POST /predict/batch` | bis zu 10.000 Flows auf einmal |
| `GET /drift` | aktueller Stand des Drift-Monitors |
| `GET /metrics` | Metriken für Prometheus |

Die Doku unter `/docs` enthält als Beispiel einen echten SSH-Brute-Force-Flow aus dem Testdatensatz.

## Live-Demo in vier Befehlen

```bash
make stack && make register && make rollout   # Modell Mo–Mi als Champion (z. B. Version 1)
make retrain                                  # Modell Mo–Do als Experiment, wird Version 2 und @champion
make demo BEFORE=1 AFTER=2                    # spielt die ganze Geschichte ab, ca. 3 Minuten
```

`make demo` rollt zuerst auf das alte Modell zurück, spielt Mittwoch und Donnerstag ab, wartet auf den
Drift-Alarm, rollt das neue Modell aus, spielt Freitag ab und zeichnet danach die Zeitleiste
[`docs/images/live_demo.png`](docs/images/live_demo.png) aus den Messwerten von Prometheus. Einzelne Tage
lassen sich mit `make replay DAY=thursday` abspielen. Der Ablauf für die Präsentation steht in
[`docs/DEMO.md`](docs/DEMO.md).

## Projektstruktur

```
├── src/ids/                  Python-Paket
│   ├── schema.py             Datenvertrag: Merkmale, Labels, Angriffskategorien
│   ├── data/download.py      Rohdaten laden und per SHA-256 prüfen
│   ├── pipeline/             DVC-Stufen: prepare, validate, split, train, evaluate, drift, plots
│   ├── metrics.py            SOC-Metriken: Erkennungsrate, Fehlalarmrate, …
│   ├── drift.py              Referenzprofil und PSI (offline und in der API)
│   ├── quality_gate.py       Freigabe-Kriterien
│   ├── registry.py           MLflow: Tracking, Registry, Champion/Challenger, Rollback
│   ├── lineage.py            Daten-Hash und Git-Commit für jedes Modell
│   ├── api/                  FastAPI-App, Schemas, Prometheus-Metriken und Drift-Monitor
│   ├── replay.py · demo.py   echten Verkehr abspielen, Live-Demo
│   ├── timeline.py           Zeitleiste aus Prometheus-Daten
│   └── evaluate_api.py       Latenz, Durchsatz, Robustheit der laufenden API
├── tests/                    68 Unit-, API- und Registry-Tests (synthetische Daten, kein Datensatz nötig)
├── monitoring/               Prometheus-Konfiguration, Alarmregeln, Grafana-Dashboard
├── docker/                   Dockerfiles für API und MLflow
├── reports/                  Berichte der Pipeline (versioniert, von CI geprüft)
├── docs/                     Demo-Ablauf, Bilder
├── dvc.yaml · params.yaml    Pipeline und Parameter
├── compose.yaml · Makefile
├── PROJEKT.md                Projektsteckbrief
└── .github/workflows/ci.yml
```

## Qualität und Reproduzierbarkeit

- **68 Tests** für jede Datenregel, die Metriken, das Quality Gate, den Drift-Monitor, die API
  (inklusive `/metrics`, Drift-Erkennung und Rückfall bei nicht erreichbarer Registry) und die Registry
  (Champion/Challenger, Rollback, skops-Rundweg gegen einen temporären MLflow-Speicher). Sie laufen
  mit synthetischen Daten im echten Schema und brauchen den 328-MB-Datensatz nicht.
- **CI baut das Modell bei jedem Push neu aus den Rohdaten** und prüft mit `git diff --exit-code`, dass
  Metriken, Drift-Bericht und Diagramme Byte für Byte mit dem Commit übereinstimmen. Gegengeprüft unter
  Linux/amd64 (CI) und macOS/arm64 (Entwicklung).
- **Deterministisch:** feste Seeds, kein Early Stopping (es würde intern zufällig aufteilen), Quantile
  ohne Interpolation, Metriken auf 4 Stellen gerundet, Diagramme als reines Vektor-SVG ohne Metadaten.
- **Lineage:** Jede Modellversion in MLflow trägt den DVC-Hash der Rohdaten und der aufbereiteten
  Daten, den Git-Commit und die Trainingstage.

## Erkenntnisse aus dem Projekt

Dinge, die erst beim Bauen aufgefallen sind – und für die die MLOps-Werkzeuge sich gelohnt haben:

- **Die Validierung hat einen Fehler gefunden, der auch in der korrigierten Fassung von 2022 noch steckt:**
  den 16-Bit-Überlauf der Header-Längen. Ohne die Regel „Zähler sind nie negativ“ wäre er unbemerkt ins
  Training gegangen.
- **Ein Modell kann selbstsicher falsch liegen.** Unsicherheit und Alarmrate eignen sich nicht als
  Drift-Signal für neue Angriffsarten – die Eingabedaten schon.
- **Der erste Drift-Ansatz war zu empfindlich.** Mit dem ganzen Trainingsverkehr als Referenz sah schon
  normaler Verkehr ohne Angriffe nach 20–40 % Drift aus, weil die Mischung aus normalem Verkehr und
  bekannten Angriffen anders war. Erst der Vergleich nur der durchgelassenen Flows mit normalem
  Trainingsverkehr trennt sauber.
- **MLflow 3 ist sicherer als erwartet:** Modelle werden mit skops statt pickle gespeichert (beim Laden
  wird kein fremder Code ausgeführt), Laden muss ausdrücklich erlaubt werden, und der Server lehnt
  unbekannte Host-Header ab (Schutz vor DNS-Rebinding). Alle drei Stellen mussten bewusst und eng
  freigegeben werden.
- **`dvc exp apply` überschreibt nicht committete Änderungen.** Seitdem gilt: vor jedem
  Experiment-Wechsel committen.

## Grenzen und nächste Schritte

- **Kleine Angriffe bleiben unsichtbar.** Botnet (736 Flows am Freitag) erkennt auch das neue Modell nur
  zu 1,9 %, und es verschiebt keine Verteilung genug für den Drift-Monitor. Ähnlich die rund 100
  Web-Angriffe am Donnerstag. Drift-Monitoring ersetzt keine Analysten.
- **Drift heißt „anders“, nicht „Angriff“.** Ein neuer, harmloser Dienst im Netz würde ebenfalls Drift
  auslösen. Der Alarm ist der Anlass, genauer hinzusehen, nicht automatisch neu zu trainieren.
- **Retraining braucht Labels.** Das Projekt nimmt an, dass die Donnerstagsdaten nach dem Alarm gelabelt
  werden. In der Praxis ist das der teuerste Schritt.
- **Nächste Schritte:** Alertmanager für Benachrichtigungen, ein Retraining-Workflow in GitHub Actions,
  der auf den Drift-Alarm reagiert, ein Feedback-Endpunkt für bestätigte Vorfälle (verzögerte Labels als
  Metrik), Shadow-Deployment des Challengers vor der Promotion.

## Quellen

- L. Liu, G. Engelen, T. Lynar, D. Essam, W. Joosen: *Error Prevalence in NIDS datasets: A Case Study
  on CIC-IDS-2017 and CSE-CIC-IDS-2018*. IEEE CNS 2022.
  [Datensatz und Dokumentation](https://intrusion-detection.distrinet-research.be/CNS2022/)
- G. Engelen, V. Rimmer, W. Joosen: *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017
  Case Study*. IEEE SPW/WTMC 2021.
- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani: *Toward Generating a New Intrusion Detection Dataset
  and Intrusion Traffic Characterization*. ICISSP 2018.

Entstanden als Abschlussprojekt der Weiterbildung *AI Engineer* (IfaDW), Block „ML Apps Deployment“.
Code unter MIT-Lizenz. Für den Datensatz gelten die Bedingungen seiner Autoren.
