# Projektsteckbrief

**Name:** Maik Hübner
**Projekt:** Intrusion Detection mit MLOps – ein Angriffserkenner, der merkt, wenn er veraltet
**Typ:** ML-Anwendung
**Repository:** https://github.com/Maik-Huebner/intrusion-detection-mlops

## Problem und Ziel

Ein Security Operations Center (SOC) bekommt jeden Tag Millionen Netzwerkverbindungen (Flows) zu sehen.
Ein ML-Modell soll Angriffe darin erkennen, also Brute Force, DoS, PortScan, Botnet und Web-Angriffe.

Das eigentliche Problem ist aber nicht das Training. Angreifer ändern ihre Methoden, und ein Modell,
das letzte Woche perfekt war, übersieht diese Woche neue Angriffsarten (**Concept Drift**). Das
Projekt zeigt den ganzen MLOps-Kreislauf, mit dem man das bemerkt und behebt:
trainieren → ausliefern → überwachen → Drift erkennen → neu trainieren → kontrolliert ausrollen.

Zielgruppe: SOC-Analysten (bekommen weniger übersehene Angriffe und wenige Fehlalarme) und das
ML-/Security-Team, das den Detektor betreibt.

## Daten

- **CIC-IDS2017, korrigierte Fassung** (Liu, Engelen et al., CNS 2022), Canadian Institute for
  Cybersecurity: fünf Arbeitstage (3.–7. Juli 2017) aufgezeichneter Netzwerkverkehr, rund 2,1 Mio. Flows
  mit 83 Merkmalen, gelabelt nach Angriffsart
- Download 328 MB, mit DVC versioniert und per SHA-256 geprüft
- Lizenz: öffentlich verfügbar für Forschung und Lehre, Nutzung mit Quellenangabe (siehe README)
- **Keine personenbezogenen Daten:** Der Verkehr stammt aus einem künstlichen Testnetz. IP-Adressen,
  Ports und Zeitstempel werden ohnehin entfernt, damit das Modell kein Shortcut-Learning betreibt.

## Modell

- **Baseline:** Ein Modell, das „alles ist harmlos“ sagt, hat auf Montag bis Mittwoch 85 % Accuracy
  und erkennt keinen einzigen Angriff. Deshalb messen wir Erkennungsrate und Fehlalarmrate statt Accuracy.
- **Modell:** `HistGradientBoostingClassifier` (scikit-learn), schnell auf Millionen Zeilen,
  deterministisch, ohne GPU
- **Drift-Szenario:** Training auf Montag bis Mittwoch, die Angriffe von Donnerstag und Freitag sind neu.

## Erfolgskriterium

| Metrik | Ziel (Quality Gate) |
|---|---|
| Erkennungsrate (Recall Angriffe) | ≥ 98 % |
| Fehlalarmrate (harmlose Flows als Angriff) | ≤ 0,5 % |
| F1 | ≥ 0,98 |

Dazu kommt ein Kriterium für den Betrieb: Das Monitoring muss den Drift am Donnerstag melden, **ohne**
die echten Labels zu kennen, und das neu trainierte Modell muss die neuen Angriffe wieder erkennen.

## Pflicht-Anforderungen (Teil 5.2)

- [x] GitHub-Repository
- [x] README
- [x] Umgebung mit festen Versionen (`pyproject.toml` + `uv.lock`)
- [x] Training mit MLflow (Tracking, Registry, Lineage zu Git und DVC)
- [x] API mit FastAPI und `/health`
- [x] Tests mit pytest
- [x] CI mit GitHub Actions
- [x] Dockerfile
- [x] Deployment (Docker Compose)

## Zusätzliche Ziele

- [x] Daten mit DVC versioniert, Pipeline mit `dvc repro`, Experimente mit `dvc exp run`
- [x] Quality Gate in CI
- [x] Model Registry in MLflow (Champion/Challenger, Rollback)
- [ ] Monitoring mit `/metrics`, Prometheus und Grafana
- [ ] Drift-Prüfung
- [ ] Evaluation der API (Latenz p50/p95, Robustheit)

## Risiken

| Risiko | Plan B |
|---|---|
| Datensatz mit 2,1 Mio. Zeilen ist für CI zu groß oder zu langsam | Rohdaten im CI-Cache; Unit-Tests laufen auf synthetischen Flows im echten Schema |
| Bekannte Fehler im Original-CIC-IDS2017 (falsche Labels, kaputte Flows) | korrigierte Fassung von 2022, eigene Validierungsstufe in der Pipeline |
| Ergebnis „zu gut, um wahr zu sein“ (100 % auf Testdaten) | zeitbasierter Split statt Zufall, ID-Spalten entfernt, Duplikate vor dem Split entfernt |
| Live-Demo fällt aus (Netz, Docker) | Screenshots von Grafana, MLflow und API in der Präsentation |

## Plan

| Tag | Ziel |
|---|---|
| vorab (13.11.) | Repository, Daten, DVC-Pipeline, Training, Quality Gate, API, Dockerfile, CI |
| 21 | Repository öffentlich, CI grün, MLflow-Server mit Registry getestet |
| 22 | Monitoring: `/metrics`, Prometheus, Grafana, Alarme |
| 23 | Drift-Prüfung, Retraining und Rollout über die Registry, Evaluation der API |
| 24 | README fertig, Präsentation, **Abgabe**: Git-Tag `abgabe` |
| 25 | Präsentation (10 Minuten + 5 Minuten Fragen) |
