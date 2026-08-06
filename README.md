# SENTRY — Explainable Security Gateway

SENTRY intercepts every tool call an AI agent wants to make, evaluates it
for safety, and explains its decision in plain English — before anything
irreversible happens.

## Quick Start (Windows)

### Prerequisites

- **Python 3.9+** — download from [python.org](https://www.python.org/downloads/)
  (make sure "Add Python to PATH" is checked during install)

### 1. Install dependencies

Open PowerShell or Command Prompt and run:

```
cd path\to\hackathon_project
pip install -r backend\requirements.txt
```

### 2. Start the server

```
python backend\main.py
```

You should see:

```
  ╔══════════════════════════════════════════════╗
  ║  SENTRY — Explainable Security Gateway       ║
  ╠══════════════════════════════════════════════╣
  ║  Dashboard:  http://127.0.0.1:8000           ║
  ║  API docs:   http://127.0.0.1:8000/docs      ║
  ║  Press Ctrl+C to stop.                       ║
  ╚══════════════════════════════════════════════╝
```

### 3. Open the dashboard

Go to **http://127.0.0.1:8000** in your browser.

### 4. Explore the API

FastAPI auto-generates interactive API docs at **http://127.0.0.1:8000/docs**
where you can try every endpoint.

## Project Structure

```
hackathon_project/
├── backend/
│   ├── main.py               # FastAPI app — starts server, mounts routes
│   ├── models.py             # Pydantic data shapes (request/response)
│   ├── audit_log.py          # In-memory audit trail
│   ├── fake_environment.py   # Fake files, emails, downloads (no real I/O)
│   └── requirements.txt      # Python dependencies
├── frontend/
│   ├── index.html            # Dashboard page
│   ├── style.css             # Dark theme styling
│   └── app.js                # Panel rendering & API calls
└── README.md                 # This file
```

## Safety Note

All actions are **simulated**. SENTRY's demo environment uses in-memory
fake files, fake emails, and fake download URLs. No real files are read,
deleted, or emailed. "Deleted" files are moved to an in-memory quarantine
folder — never actually removed.

## Current Phase

- **Phase 1** ✅ Server running, dashboard visible, fake data in memory
- **Phase 2** 🔲 Decision engine, content scanner, working demo scenarios
