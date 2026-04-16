# ICOC-Lite — VOC/AI Module (Member 3)

Vulnerability Operations Center + AI Risk Engine
Built with FastAPI · React · scikit-learn · VirusTotal API

---

## 🗂️ Project Structure

```
icoc-lite/
├── voc/                          # VOC Module (FR-VOC-01..07)
│   ├── fr_voc_01_inventory.py    # FR-VOC-01: Software inventory
│   ├── fr_voc_02_cvss_scoring.py # FR-VOC-02: CVSS v3.1 scoring
│   ├── fr_voc_03_patch_tracking.py # FR-VOC-03: Patch tracking
│   ├── fr_voc_04_reports.py      # FR-VOC-04: Vulnerability reports
│   ├── fr_voc_05_scanner.py      # FR-VOC-05: On-demand scanner + VT
│   ├── fr_voc_06_nvd_integration.py # FR-VOC-06: NVD/CVE database
│   ├── fr_voc_07_compliance.py   # FR-VOC-07: PCI-DSS, ISO 27001, NIST
│   └── virustotal_client.py      # VirusTotal API v3 client
│
├── ai/                           # AI Module (FR-AI-01..07)
│   ├── fr_ai_01_risk_score.py    # FR-AI-01: Global risk score (0-100)
│   ├── fr_ai_02_ml_prioritization.py # FR-AI-02: ML alert prioritization
│   ├── fr_ai_03_correlation.py   # FR-AI-03: SOC × VOC correlation
│   ├── fr_ai_05_07.py            # FR-AI-04..07: Realtime, TI, predict, recs
│   ├── train.py                  # ML training pipeline
│   └── models/
│       ├── exploitability_model.py # Regression: predict CVSS score
│       ├── severity_classifier.py  # Multi-class: Critical/High/Medium/Low
│       └── anomaly_detector.py     # Isolation Forest anomaly detection
│
├── frontend/                     # React dashboard
│   └── src/App.jsx               # Full dashboard (5 tabs)
│
├── main.py                       # FastAPI server (all endpoints)
├── docker-compose.yml
├── requirements.txt
└── .env                          # API keys + config
```

---

## 🚀 Quick Start (Docker — recommended)

```bash
# 1. Clone / unzip project
cd icoc-lite

# 2. Start full stack (API + Frontend)
docker-compose up --build

# 3. Train ML models (IMPORTANT — do this first)
docker exec icoc-api python ai/train.py --synthetic

# OR with real NVD data (slower, needs internet):
docker exec icoc-api python ai/train.py --download --years 2022 2024

# 4. Open dashboard
open http://localhost:3000

# 5. API docs (Swagger UI)
open http://localhost:8000/docs
```

---

## ⚙️ Without Docker (local Python)

```bash
# Install deps
pip install -r requirements.txt

# Start API
python main.py
# → API at http://localhost:8000

# Train models
python ai/train.py --synthetic    # fast, offline
python ai/train.py --download     # real NVD data

# Start frontend
cd frontend
npm install
npm run dev
# → UI at http://localhost:3000
```

---

## 🤖 ML Models

| Model | Type | Input | Output |
|-------|------|-------|--------|
| `exploitability_model` | GradientBoosting Regressor | CVSS vector features | Score 0–10 |
| `severity_classifier` | RandomForest + Calibration | CVSS vector + score | Critical/High/Medium/Low |
| `anomaly_detector` | Isolation Forest | CVE feature vector | Anomaly flag + score |

Training data: **NIST NVD API 2.0** (real CVEs, 2021–2024) or synthetic fallback.

---

## 🔑 API Endpoints

### VOC
| Method | Path | Description |
|--------|------|-------------|
| GET | `/voc/inventory` | FR-VOC-01: Software inventory |
| GET | `/voc/cvss/{cve_id}` | FR-VOC-02: CVSS v3.1 score |
| GET | `/voc/patches` | FR-VOC-03: Patch status |
| POST | `/voc/patches/apply` | FR-VOC-03: Mark patch applied |
| GET | `/voc/report` | FR-VOC-04: Vulnerability report |
| GET | `/voc/report/csv` | FR-VOC-04: CSV export |
| POST | `/voc/scan` | FR-VOC-05: Trigger scan |
| GET | `/voc/nvd/recent` | FR-VOC-06: Recent NVD CVEs |
| GET | `/voc/compliance` | FR-VOC-07: Compliance report |

### VirusTotal
| Method | Path | Description |
|--------|------|-------------|
| POST | `/vt/hash` | Check file hash |
| POST | `/vt/ip` | Check IP reputation |
| POST | `/vt/url` | Check URL |

### AI
| Method | Path | Description |
|--------|------|-------------|
| GET | `/ai/risk-score` | FR-AI-01: Global risk score |
| POST | `/ai/prioritize` | FR-AI-02: ML alert ranking |
| POST | `/ai/correlate` | FR-AI-03: SOC × VOC correlation |
| GET | `/ai/risk-stream` | FR-AI-04: SSE live updates |
| GET | `/ai/threat-intel` | FR-AI-05: TI feed |
| GET | `/ai/predict-incident` | FR-AI-06: Incident probability |
| GET | `/ai/recommendations` | FR-AI-07: Response recs |
| GET | `/ai/anomalies` | Anomaly detection |
| GET | `/ai/train-status` | Model readiness check |

### Dashboard
| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | All data in one call |

---

## 🌐 Demo Mode

`DEMO_MODE=true` in `.env` means:
- No real network scanning required
- Uses synthetic lab hosts (192.168.100.x)
- All VT API calls still hit VirusTotal live (real results)
- ML training uses generated or cached NVD data

Set `DEMO_MODE=false` for real nmap scanning (requires root + network access).

---

## 🔐 VirusTotal API

Your API key is pre-configured in `.env`.
Free tier: 4 requests/minute, 500/day.
Results cached locally for 24h in `voc/data/vt_cache/`.

Known test IOCs:
- Hash (EICAR): `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
- Malicious IP: `45.33.32.156`
