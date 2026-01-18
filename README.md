# Application for malware detection

## Setup

From root folder we have to run

`setup.bat`

### Api

- Locatie: http://localhost:30001/

### Grafana

- Locatie: http://localhost:30080/

## Autoscaling

Open 3 cmd windows and run one command in each one.

`kubectl get hpa -w`

`kubectl get pods -w`

`python  scripts\stress_test.py`

## Grafana setup

Enter "Connections" tab -> Add data source -> prometheus -> fill Prometheus server URL with "http://prometheus:9090" -> press "Save & Test"

Enter "Dashboard" tab -> Create dashboard -> Import -> Add Json from GrafanaConfigurations and press Load
