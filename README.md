# RansomGuardUp

**Ransomware Early-Stage Detector and Safe Backup Orchestrator**

A real-time ransomware detection system that combines seven independent heuristic analysers with a Random Forest machine learning classifier, coordinated through an event-driven architecture. The system monitors file system activity, correlates weighted threat signals within a five-second window, and responds automatically with alerting, process suspension, and file quarantine. An integrity-verified backup orchestrator maintains versioned file snapshots with SHA-256 checksum validation for recovery.

## Architecture

The system is built around an asynchronous event-driven architecture using Python's `asyncio`. All components communicate exclusively through a shared in-process publish-subscribe event bus with no direct coupling between producers and consumers.

**Detection Pipeline:**

```
File System Events → Event Bus → 7 Analysers → Scoring Engine → Response Orchestrator
                                                                        ↓
                                                              Backup Orchestrator
```

**Detection Signals:**

| Signal | Weight | Description |
|--------|--------|-------------|
| Honeyfile Touched | 60 | Decoy file accessed or modified |
| Ransom Note | 50 | Known ransom note filename pattern detected |
| Extension Renamed | 40/24/13 | Known bad / double extension / any change |
| ML Prediction | 24-35 | Random Forest classifier (scales with probability) |
| Type Mutation | 25 | Magic bytes no longer match file extension |
| Burst Activity | 20 | File operations per second exceed threshold |
| High Entropy | 15 | Shannon entropy approaching 8.0 bits/byte |

**Response Thresholds:** Alert ≥ 30 / Suspend ≥ 55 / Quarantine ≥ 75

## Requirements

- Python 3.12+
- Windows, macOS, or Linux

## Installation

```bash
git clone https://github.com/rnicoras/ransomware-detector.git
cd ransomware-detector
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Configuration

All settings are defined in `config/default.yaml`:

```yaml
monitor:
  watch_paths:
    - "~/Documents"
    - "~/Desktop"
  recursive: true

honeyfiles:
  enabled: true
  count: 5

threat_scoring:
  thresholds:
    alert: 30
    suspend: 55
    quarantine: 75

response:
  auto_suspend: false
  auto_quarantine: true

backup:
  enabled: true
  max_versions: 5
  interval_seconds: 300

dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 8765
```

A custom configuration file can be passed at runtime using the `--config` flag. Only the values to override need to be specified.

## Running the Detector

```bash
python main.py --config config/default.yaml
```

The detector will:
1. Start monitoring the configured watch paths
2. Plant honeyfile decoys across monitored directories
3. Run an initial backup of all monitored files
4. Launch the real-time dashboard at `http://127.0.0.1:8765`

Stop with `Ctrl+C` for a graceful shutdown.

Override watch paths from the command line:

```bash
python main.py --watch ~/Desktop/target
```

## Machine Learning Pipeline

The ML component uses a Random Forest classifier trained on the [NapierOne](https://github.com/simonrdavies/NapierOne) academic dataset.

### Dataset

Download NapierOne from:
- GitHub: https://github.com/simonrdavies/NapierOne
- AWS Open Data: https://registry.opendata.aws/napierone/

Select 1,000 files from each of the 10 benign categories (docx, xlsx, pptx, doc, pdf, jpg, png, txt, csv, zip) and 1,000 from each of the 4 ransomware families (Dharma, Maze, Phobos, Ryuk), totalling 14,000 files. Place them under a `data/` folder in the project root.

### Feature Extraction

```bash
python ml/extract.py --data data/ --out ml/features.csv
```

Extracts four features per file:
- **Shannon entropy** — byte-level randomness (0.0 to 8.0)
- **File size** — raw byte count
- **Chi-square statistic** — byte distribution uniformity, normalised by length
- **Magic byte match** — whether the file header matches the declared extension

### Model Training

```bash
python ml/training.py --features ml/features.csv --out models/ransomware_detector.joblib
```

Hyperparameters:

| Parameter | Value |
|-----------|-------|
| n_estimators | 100 |
| max_depth | 20 |
| min_samples_split | 5 |
| min_samples_leaf | 2 |
| random_state | 42 |

The trained model is saved to `models/ransomware_detector.joblib`. If the model file is absent at runtime, the ML scorer is disabled and all other analysers continue to operate normally.

## Demo Simulation

A purpose-built attack simulation script tests the complete detection pipeline using four encryption algorithms representative of real ransomware families.

### Setup

```bash
pip install pycryptodome cryptography
```

### Commands

```bash
# Create sample target files
python simulation.py setup

# Start the detector
python main.py --config config/default.yaml

# Open dashboard at http://127.0.0.1:8765

# Run the simulated attack (in a second terminal)
python simulation.py attack

# Clean up all demo artifacts
python simulation.py cleanup
```

### Encryption Algorithms

| Algorithm | Extension | Used By |
|-----------|-----------|---------|
| AES-256-CBC | .locked | WannaCry, Dharma, Ryuk |
| AES-256-CTR | .enc | Maze, Conti |
| ChaCha20 | .wncry | STOP/Djvu |
| Fernet | .dharma | Python-based ransomware |

The simulation triggers all seven detection signals: honeyfile access, burst activity, high entropy, type mutation, extension renaming, ransom note creation, and ML classification.

## Project Structure

```
ransomware-detector/
├── main.py                          # Application entry point
├── config/
│   └── default.yaml                 # Default configuration
├── models/
│   └── ransomware_detector.joblib   # Trained ML model
├── ml/
│   ├── extract.py                   # Feature extraction script
│   └── training.py                  # Model training script
├── src/
│   ├── bus.py                       # Async pub/sub event bus
│   ├── events.py                    # Event and signal dataclasses
│   ├── settings.py                  # YAML config loader
│   ├── logger.py                    # JSON structured logging
│   ├── monitoring/
│   │   ├── watcher.py               # File system watcher (watchdog)
│   │   ├── honeyfiles.py            # Honeyfile sentinel
│   │   └── process.py               # Process I/O inspector
│   ├── analysis/
│   │   ├── engine.py                # Analysis engine coordinator
│   │   ├── burst.py                 # Burst detector
│   │   ├── entropy.py               # Shannon entropy analyser
│   │   ├── typemutation.py          # Magic byte mismatch detector
│   │   ├── extension_rename.py      # Extension rename detector
│   │   ├── ransomnote.py            # Ransom note filename detector
│   │   ├── ml_scorer.py             # Random Forest ML scorer
│   │   └── score.py                 # Threat scoring engine
│   ├── response/
│   │   └── orchestrator.py          # Alert / suspend / quarantine
│   ├── backup/
│   │   ├── orchestrator.py          # Versioned backup manager
│   │   └── integrity.py             # SHA-256 checksum database
│   ├── platform/
│   │   ├── pidresolver.py           # PID ↔ file handle resolver
│   │   └── process_control.py       # Process suspend / resume / kill
│   └── dashboard/
│       ├── server.py                # FastAPI + WebSocket backend
│       ├── index.html               # Dashboard frontend
│       ├── style.css                # Dashboard styles
│       └── socket.js                # WebSocket client
├── simulation.py                    # Attack simulation script
├── requirements.txt                 # Python dependencies
└── tests/                           # Test suite
```

## Dashboard

The real-time web dashboard at `http://127.0.0.1:8765` displays:
- Summary counters for alerts, suspensions, quarantines, and uptime
- A scrolling event feed with threat assessments and response actions
- Colour-coded severity: grey (assessment), yellow (alert), orange (suspend), red (quarantine)
- Full file paths, contributing signal names, and process identifiers

The server retains the last 100 events and replays them to any client that connects or reconnects.

## Technologies

| Technology | Role |
|------------|------|
| Python 3.12 | Primary language with native asyncio |
| watchdog | Cross-platform file system monitoring |
| psutil | Process inspection, I/O counters, process control |
| scikit-learn | Random Forest training and inference |
| FastAPI + uvicorn | Async web server with WebSocket support |
| SQLite | Checksum storage for backup integrity (WAL mode) |
| PyYAML | Configuration file parsing |

## Author

**Radu Nicoraș** — West University of Timișoara, Faculty of Mathematics and Computer Science

Bachelor's thesis supervised by Asist. Dr. Florin Roșu, 2026.
