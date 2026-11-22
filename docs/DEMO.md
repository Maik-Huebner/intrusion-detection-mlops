# Drehbuch für die Live-Demo (3 Minuten)

Ziel der Demo: Das Publikum sieht, dass das alte Modell neue Angriffe **nicht** erkennt, dass das
Monitoring es **trotzdem** merkt, dass die LLM-Notiz davor warnt, der Typ-Zuordnung zu trauen, und dass ein
neues Modell über die Registry ausgerollt wird.

## Vorbereitung (vor der Präsentation, ca. 10 Minuten)

```bash
cd intrusion-detection-mlops
open -a Docker                       # Docker Desktop starten, falls es nicht läuft
make stack                           # MLflow, API, Prometheus, Grafana, Ollama
curl -s localhost:8000/model         # antwortet die API? Welche Version?
```

Welche Registry-Versionen sind das alte (Mo–Mi) und das neue Modell (Mo–Do)? In MLflow
(http://localhost:5050 → Models → ids-detector) steht es am Run-Namen `train mon+tue+wed` bzw.
`train mon+tue+wed+thu`. Lokal sind das zurzeit **v5** (alt) und **v6** (neu). Die Versionen 1–4 stammen
aus früheren Projektständen (ohne Drift-Profil bzw. ohne Typ-Modell).

Folgende Tabs im Browser öffnen, in dieser Reihenfolge:

| Tab | Adresse | Wofür |
|---|---|---|
| 1 | http://localhost:3001 | Grafana-Dashboard, Zeitraum „Last 5 minutes“ |
| 2 | http://localhost:9090/alerts | Prometheus-Alarme |
| 3 | http://localhost:5050/#/models/ids-detector | MLflow-Registry mit den Aliasen |
| 4 | http://localhost:8000/docs | API-Doku (falls Fragen kommen) |

Dazu ein Terminal mit großer Schrift im Projektordner.

Kurz vorher auf das alte Modell zurückstellen und das LLM einmal aufwärmen (die erste Notiz lädt das
Modell in den Speicher und kann länger dauern):

```bash
make rollback V=5
make note DAY=tuesday LABEL=SSH-Patator
```

## Ablauf

| Zeit | Befehl | Was man zeigt und sagt |
|---|---|---|
| 0:00 | `make replay DAY=wednesday` | Grafana: rote Fläche = Alarme. „Das Modell kennt DoS vom Mittwoch: 100 % erkannt, kein Drift.“ |
| 0:35 | `make replay DAY=thursday` | Grafana: alles grün, Alarmrate 0 %. Terminal: **0 % erkannt**. „Das Modell ist blind und merkt es nicht.“ Dann: Kachel **DRIFT** wird rot. „Der Monitor schaut auf die Daten, nicht auf das Modell.“ |
| 1:15 | Tab 2 | Prometheus: `IdsDataDrift` **firing**. „Hier würde jetzt jemand benachrichtigt.“ |
| 1:25 | `make note DAY=friday LABEL=DDoS` | Terminal: wahres Label DDoS, Typ-Modell sagt **DoS Hulk, 99,9 % sicher** – falsch. Die Notiz endet mit „**Achtung, Drift:** Die Zuordnung kann falsch sein“. „Das LLM entscheidet nichts, es formuliert – und es weiß vom Drift-Monitor.“ |
| 1:55 | `make rollback V=6` | Tab 3: `@champion` zeigt auf v6. „Das Modell mit Donnerstag ist schon trainiert und hat den Champion/Challenger-Vergleich gewonnen – Rollout ist nur ein Neustart der API.“ Grafana: Version springt auf **v6**. |
| 2:20 | `make replay DAY=friday` | Terminal: **99 % erkannt**, Freitag hat keines der Modelle je gesehen. Grafana: Drift wieder OK. |
| 2:50 | – | „Daten, Pipeline, Registry, Monitoring, Notiz, Rollout – der Kreislauf ist geschlossen.“ |

Hinweise:

- In der Demo heißt das Ausrollen von v6 `make rollback V=6`, weil v6 schon registriert ist. Der echte Weg
  nach einem Alarm ist `make retrain` (DVC-Experiment, Registrierung, Champion/Challenger) und danach
  `make rollout`. Das dauert rund zwei Minuten und lohnt sich live nur, wenn Zeit ist.
- Braucht das LLM zu lange (über 60 s) oder ist es nicht da, kommt die Notiz aus der Vorlage
  (`note from fallback`). Auch das ist eine gute Antwort auf die Frage „Was, wenn das LLM ausfällt?“.
- Alles in einem Durchlauf (ohne Pausen zum Erklären): `make demo BEFORE=5 AFTER=6`.

## Plan B

Wenn Docker, das Netz oder der Laptop streiken, zeigen die Folien die Bilder aus einem echten Lauf:

- [`images/live_demo.png`](images/live_demo.png) – die ganze Demo als Zeitleiste, gemessen von Prometheus
- [`images/grafana_drift.jpg`](images/grafana_drift.jpg) – Dashboard im Moment des Alarms (v5, DRIFT)
- [`images/grafana_family_llm.jpg`](images/grafana_family_llm.jpg) – Alarme nach Angriffsfamilie und LLM-Notizen
- [`images/prometheus_alert.png`](images/prometheus_alert.png) – der Alarm `IdsDataDrift` in Prometheus

## Wenn etwas hakt

| Symptom | Ursache und Lösung |
|---|---|
| `/model` zeigt `"fallback": true` | Die API hat die Registry beim Start nicht erreicht. `docker compose --env-file local.env ps` prüfen, dann `make rollout`. |
| Notiz kommt immer aus der Vorlage (`not_configured` oder `APIConnectionError`) | Ollama läuft nicht oder das Modell fehlt: `make llm`, dann erneut versuchen. |
| Notiz dauert sehr lange | Speicher knapp: In Docker Desktop mehr RAM geben (mindestens 8 GB) oder Grafana kurz stoppen. |
| Grafana zeigt „No data“ | Zeitraum auf „Last 5 minutes“ stellen; Prometheus → Status → Target health muss `ids-api` als UP zeigen. |
| Drift bleibt nach dem Donnerstag bei OK | Das Fenster braucht mindestens 500 durchgelassene Flows: Replay noch einmal starten. |
| Port 3000 belegt | `GRAFANA_PORT` in `local.env` anpassen (Standard hier: 3001). |
| Port 5000 belegt (macOS AirPlay) | deshalb läuft MLflow auf 5050 (`MLFLOW_PORT` in `local.env`). |

Nach der Präsentation: `make stop` beendet den Stack. Die Volumes mit MLflow-, Prometheus- und
Ollama-Daten bleiben erhalten.
