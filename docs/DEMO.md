# Drehbuch für die Live-Demo (3 Minuten)

Ziel der Demo: Das Publikum sieht, dass das alte Modell neue Angriffe **nicht** erkennt, dass das
Monitoring es **trotzdem** merkt und dass ein neues Modell über die Registry ausgerollt wird.

## Vorbereitung (vor der Präsentation, ca. 10 Minuten)

```bash
cd intrusion-detection-mlops
open -a Docker                       # Docker Desktop starten, falls es nicht läuft
make stack                           # MLflow, API, Prometheus, Grafana
curl -s localhost:8000/model         # antwortet die API? Welche Version?
```

Welche Registry-Versionen sind das alte (Mo–Mi) und das neue Modell (Mo–Do)? In MLflow
(http://localhost:5050 → Models → ids-detector) steht es am Run-Namen `train mon+tue+wed` bzw.
`train mon+tue+wed+thu`. Lokal sind das zurzeit **v3** (alt) und **v4** (neu). Die Versionen 1 und 2
stammen aus der Zeit vor dem Drift-Profil und haben kein Drift-Monitoring.

Folgende Tabs im Browser öffnen, in dieser Reihenfolge:

| Tab | Adresse | Wofür |
|---|---|---|
| 1 | http://localhost:3001 | Grafana-Dashboard, Zeitraum „Last 5 minutes“ |
| 2 | http://localhost:9090/alerts | Prometheus-Alarme |
| 3 | http://localhost:5050/#/models/ids-detector | MLflow-Registry mit den Aliasen |
| 4 | http://localhost:8000/docs | API-Doku (falls Fragen kommen) |

Dazu ein Terminal mit großer Schrift im Projektordner.

Kurz vorher einmal auf das alte Modell zurückstellen, damit die Demo mit v3 beginnt:

```bash
make rollback V=3
```

## Ablauf

| Zeit | Befehl | Was man zeigt und sagt |
|---|---|---|
| 0:00 | `make replay DAY=wednesday` | Grafana: rote Fläche = Alarme. „Das Modell kennt DoS vom Mittwoch: 100 % erkannt, kein Drift.“ |
| 0:40 | `make replay DAY=thursday` | Grafana: alles grün, Alarmrate 0 %. Terminal: **0 % erkannt**. „Das Modell ist blind und merkt es nicht.“ Dann: Kachel **DRIFT** wird rot, Drift-Kurve über der Linie. „Der Monitor schaut auf die Daten, nicht auf das Modell.“ |
| 1:30 | Tab 2 | Prometheus: `IdsDataDrift` **firing**. „Hier würde jetzt jemand benachrichtigt.“ |
| 1:45 | `make rollback V=4` | Tab 3: `@champion` zeigt auf v4. „Das Modell mit Donnerstag ist schon trainiert und hat den Champion/Challenger-Vergleich gewonnen – Rollout ist nur ein Neustart der API.“ Grafana: Version springt auf **v4**. |
| 2:15 | `make replay DAY=friday` | Terminal: **99 % erkannt**, Freitag hat keines der Modelle je gesehen. Grafana: Drift wieder OK. |
| 2:50 | – | „Daten, Pipeline, Registry, Monitoring, Rollout – der Kreislauf ist geschlossen.“ |

Hinweis: In der Demo heißt das Ausrollen von v4 `make rollback V=4`, weil v4 schon registriert ist.
Der echte Weg nach einem Alarm ist `make retrain` (DVC-Experiment, Registrierung, Champion/Challenger)
und danach `make rollout`. Das dauert rund zwei Minuten und lohnt sich live nur, wenn Zeit ist.

Alles in einem Durchlauf (ohne Pausen zum Erklären): `make demo BEFORE=3 AFTER=4`.

## Plan B

Wenn Docker, das Netz oder der Laptop streiken, zeigen die Folien die Bilder aus einem echten Lauf:

- [`images/live_demo.png`](images/live_demo.png) – die ganze Demo als Zeitleiste, gemessen von Prometheus
- [`images/grafana_drift.jpg`](images/grafana_drift.jpg) – Dashboard im Moment des Alarms (v3, DRIFT)
- [`images/grafana_after_rollout.jpg`](images/grafana_after_rollout.jpg) – Dashboard nach dem Rollout (v4)
- [`images/prometheus_alert.png`](images/prometheus_alert.png) – der Alarm `IdsDataDrift` in Prometheus

## Wenn etwas hakt

| Symptom | Ursache und Lösung |
|---|---|
| `/model` zeigt `"fallback": true` | Die API hat die Registry beim Start nicht erreicht. `docker compose --env-file local.env ps` prüfen, dann `make rollout`. |
| Grafana zeigt „No data“ | Zeitraum auf „Last 5 minutes“ stellen; Prometheus → Status → Target health muss `ids-api` als UP zeigen. |
| Drift bleibt nach dem Donnerstag bei OK | Das Fenster braucht mindestens 500 durchgelassene Flows: Replay noch einmal starten. |
| Port 3000 belegt | `GRAFANA_PORT` in `local.env` anpassen (Standard hier: 3001). |
| Port 5000 belegt (macOS AirPlay) | deshalb läuft MLflow auf 5050 (`MLFLOW_PORT` in `local.env`). |

Nach der Präsentation: `make stop` beendet den Stack. Die Volumes mit MLflow- und Prometheus-Daten
bleiben erhalten.
