# Phishing Triage – SOC Analyst Forensics Frontend

A lightweight, high-performance SOC analyst dashboard for automated email forensics and phishing triage. Analysts upload suspicious `.eml` or `.msg` files, and the platform surfaces envelope metadata, Received routing hops, SPF/DKIM/DMARC authentication checks, URL reputation verdicts, attachment cryptographic digests, and an aggregated 0–100 Phishing Risk Score.

Designed with a dark, refined, security-operations aesthetic based on Charcoal (`#1E1E1C`) and Sand (`#D8CBB3`). Built using pure standard web technologies with **zero build step**, meaning it can be served directly by Flask, FastAPI, Nginx, or opened standalone in any modern browser.

---

## Table of Contents
1. [Features](#features)
2. [Tech Stack](#tech-stack)
3. [Project Structure](#project-structure)
4. [Quick Start (Standalone with Mock Data)](#quick-start-standalone-with-mock-data)
5. [Connecting to a Live Backend](#connecting-to-a-live-backend)
6. [Serving with Python Frameworks](#serving-with-python-frameworks)
   - [Flask](#flask-example)
   - [FastAPI](#fastapi-example)
7. [API Contract & Schema Specification](#api-contract--schema-specification)
8. [Frontend Security Architecture](#frontend-security-architecture)

---

## Features

- **Dashboard Operations Center (`index.html`)**: Real-time SOC triage metrics, 7-day threat volume trend, verdict distribution donut chart, and recent investigations table.
- **Email Upload Staging Zone (`analyze.html`)**: High-contrast drag-and-drop zone with client-side format (`.eml`, `.msg`) and file size (10 MB limit) enforcement.
- **Forensic Investigation Report (`report.html`)**:
  - **Animated Risk Gauge (0–100)**: Visual donut gauge color-coded by severity (`Clean`, `Suspicious`, `Malicious`).
  - **Envelope & Header Forensics**: Plaintext-sanitized body viewer, Message-ID with one-click copy.
  - **Authentication Checks**: SPF, DKIM, DMARC badges with tooltips and detailed spoofing indicator flags.
  - **Mail Routing Path (Received:)**: Vertical timeline tracing origin server IP, country geolocation, and hop delays.
  - **Defanged URL Reputation**: Auto-defangs URLs (`hxxp://`, `[.]`) with safe reveal toggles, threat-intel verdicts, and flagged-only filtering.
  - **Cryptographic Attachment Digests**: Flags dangerous executable extensions (`.exe`, `.scr`, `.vbs`, `.js`), provides one-click MD5 / SHA-256 hash copying, and displays detection ratios.
  - **Risk Score Breakdown**: Horizontal bar chart visualizing individual penalty weights.
  - **Action Toolbar**: Export to JSON, CSV, or formatted print/PDF, re-analyze against live feeds, delete record, and copy all IOCs.
- **Archive & History (`history.html`)**: Paginated table with text search, verdict filter, column sorting, and inline deletion.
- **Preferences (`settings.html`)**: Runtime API endpoint configuration, display density modes (Comfortable vs. Compact), and default defanging toggles.

---

## Tech Stack

| Technology | Implementation | Description |
|---|---|---|
| **Markup & Layout** | HTML5, Semantic Elements | WCAG AA contrast, keyboard navigable, full ARIA roles |
| **CSS Framework** | Bootstrap 5.3 (CDN) + Custom Tokens | Charcoal `#1E1E1C` & Sand `#D8CBB3` dark theme tokens |
| **Icons** | Bootstrap Icons 1.11.3 (CDN) | Security & forensics iconography |
| **Visualizations** | Chart.js 4.4 (CDN) | Donut distribution & line volume charts |
| **Typography** | Google Fonts (`Inter` & `JetBrains Mono`) | Clean UI typography + monospace technical data |
| **Scripting** | Vanilla JavaScript (ES Modules) | No React/Vue/Node build step; zero bundling required |

---

## Project Structure

```
/frontend
  ├── index.html              # SOC Dashboard (KPIs, charts, recent queue)
  ├── analyze.html            # Drag-and-drop upload & staging zone
  ├── report.html             # Forensic analysis investigation report
  ├── history.html            # Archive with search, filters, and pagination
  ├── settings.html           # Platform preferences & API endpoint settings
  ├── 404.html                # Not-found fallback page
  ├── README.md               # Architecture, API contract, and deployment guide
  │
  ├── css/
  │   ├── tokens.css          # Color variables, typography, spacing, elevations
  │   ├── main.css            # Layout shell, sidebar, topbar, responsive rules
  │   ├── components.css      # Cards, tables, badges, risk gauge, timeline, toasts
  │   └── print.css           # Black-and-white print stylesheet for PDF exports
  │
  ├── js/
  │   ├── config.js           # Central constants (API_BASE_URL, USE_MOCK, MAX_SIZE)
  │   ├── api.js              # Single HTTP fetch client for all endpoints
  │   ├── mock-data.js        # High-risk, medium-risk, clean mock emails & stats
  │   ├── utils.js            # Defang/refang, copyToClipboard, formatters, IOC parser
  │   ├── ui.js               # Toasts, modals, skeletons, error banners, tooltips
  │   ├── layout.js           # Shared sidebar collapse, mobile drawer & healthcheck
  │   ├── dashboard.js        # Dashboard data loading & Chart.js instances
  │   ├── analyze.js          # Drag-and-drop file upload & progress handlers
  │   ├── report.js           # Report data rendering, gauge animation, IOC copy
  │   ├── history.js          # Search, pagination, and sorting for archive
  │   └── settings.js         # Settings form controller & localStorage persistence
  │
  └── assets/
      ├── logo.svg            # Sand shield with mail icon
      └── favicon.svg         # Favicon icon
```

---

## Quick Start (Standalone with Mock Data)

The application comes preconfigured in **mock mode** (`USE_MOCK = true` in `js/config.js`). It includes realistic phishing samples:
- `a1b2c3`: High-risk invoice phishing email (Risk Score: 87, malicious `.exe`, DMARC fail).
- `d4e5f6`: Suspicious meeting invite (Risk Score: 45, suspicious link, SPF softfail).
- `g7h8i9`: Clean cybersecurity newsletter (Risk Score: 8, all checks passed).

### Running Locally:
Because the code uses standard ES modules (`import`/`export`), it should be served via an HTTP server rather than double-clicked via `file://`:

```bash
# Using Python 3:
cd frontend
python -m http.server 8080

# Or using Node:
npx serve .
```
Open [http://localhost:8080](http://localhost:8080) in your web browser.

---

## Connecting to a Live Backend

All backend communication is centralized inside `js/api.js`. To switch from simulated mock data to your live Python backend:

1. Open `js/config.js` and update:
   ```javascript
   export const API_BASE_URL = 'http://localhost:5000/api'; // or '/api'
   export const USE_MOCK = false;
   ```
2. Alternatively, navigate to **Settings** (`settings.html`) in the application UI, update the **API Base Endpoint**, and toggle off **Mock Mode**.

---

## Serving with Python Frameworks

### Flask Example

```python
from flask import Flask, send_from_directory
import os

app = Flask(__name__, static_folder='frontend', static_url_path='')

@app.route('/')
def serve_index():
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join('frontend', path)):
        return send_from_directory('frontend', path)
    return send_from_directory('frontend', '404.html'), 404

# Register your API routes (e.g., /api/analyze, /api/analyses, /api/stats) here...

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

### FastAPI Example

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI(title="Phishing Triage API")

# Register your API routers first:
# app.include_router(forensics_router, prefix="/api")

# Mount frontend static directory:
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
```

---

## API Contract & Schema Specification

The frontend connects to the following RESTful endpoints:

### Endpoints Overview

| Method | Endpoint | Description | Request Payload | Response Payload |
|---|---|---|---|---|
| `POST` | `/api/analyze` | Parse and analyze an email file | `multipart/form-data` with `file` | Analysis JSON (Contract below) |
| `GET` | `/api/analyses` | List past investigations | Query: `page`, `limit`, `verdict`, `q` | `{ "items": [...], "total": 128 }` |
| `GET` | `/api/analyses/{id}` | Get full report details | None | Analysis JSON |
| `DELETE` | `/api/analyses/{id}` | Delete investigation | None | `204 No Content` or `null` |
| `GET` | `/api/analyses/{id}/export` | Export report | Query: `format=json\|csv\|pdf` | File blob (JSON/CSV/PDF) |
| `GET` | `/api/stats` | Dashboard KPIs and chart telemetry | None | Stats JSON |
| `GET` | `/api/health` | Backend connectivity check | None | `{ "status": "ok", "version": "1.0" }` |

---

### Analysis JSON Schema (Strict Contract)

```json
{
  "id": "a1b2c3",
  "filename": "invoice_payment.eml",
  "analyzed_at": "2026-11-19T10:32:00Z",
  "risk": {
    "score": 87,
    "verdict": "malicious",
    "breakdown": [
      { "factor": "DMARC fail", "points": 25 },
      { "factor": "Malicious URL detected", "points": 20 }
    ]
  },
  "envelope": {
    "from": "billing@fake-paypal.com",
    "reply_to": "support@paypalsecure-update.com",
    "to": "john.doe@acmecorp.com",
    "subject": "Urgent: Your invoice #INV-29847 is ready",
    "date": "2026-11-19T09:14:22Z",
    "message_id": "<5f8a3b2c.1a2b3c@fake-paypal.com>",
    "body_text": "Please review and pay your outstanding invoice immediately..."
  },
  "authentication": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail",
    "spoofing_indicators": [
      "Return-Path domain mismatch",
      "Display name impersonation (PayPal)"
    ]
  },
  "routing": [
    {
      "hop": 1,
      "from": "mail-out.fake-paypal.com",
      "by": "mx1.shady-relay.net",
      "ip": "185.234.72.19",
      "timestamp": "2026-11-19T09:14:25Z",
      "country": "RU"
    }
  ],
  "urls": [
    {
      "url": "https://fake-paypal.com/invoice/29847",
      "domain": "fake-paypal.com",
      "verdict": "malicious",
      "detections": 48,
      "total_engines": 90,
      "source": "VirusTotal"
    }
  ],
  "attachments": [
    {
      "filename": "Invoice_29847.exe",
      "extension": ".exe",
      "size_bytes": 245760,
      "md5": "e99a18c428cb38d5f260853678922e03",
      "sha256": "a3f5b7d12c9e84f6a1b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
      "dangerous_extension": true,
      "verdict": "malicious",
      "detections": 61,
      "total_engines": 72
    }
  ]
}
```

#### Allowed Enum Values:
- **`risk.verdict` / `urls[].verdict` / `attachments[].verdict`**: `"clean"` | `"suspicious"` | `"malicious"` | `"unknown"`
- **`authentication.spf` / `dkim` / `dmarc`**: `"pass"` | `"fail"` | `"softfail"` | `"neutral"` | `"none"`

---

## Frontend Security Architecture

To protect SOC analysts from active malware:
1. **Zero Raw HTML Injection**: All email envelope headers, subjects, sender fields, and message bodies are inserted using `textContent` or sanitized DOM nodes. Raw email HTML is **never rendered**.
2. **Defanged URLs by Default**: Extracted URLs are transformed (`hxxp://`, `[.]`) to eliminate accidental click navigation to live command-and-control servers.
3. **No External Asset Calls**: Email bodies never trigger outbound requests for remote tracking beacons, CSS, or embedded images.
4. **Pre-flight Validation**: Client-side extension validation stops accidental uploads of unsupported binary formats before hitting the backend parser.
