# Sec Ops One Shots

Sec Ops One Shots is a collection of standalone, self-contained Python scripts for automating common tasks in security operations. Each script focuses on one specific function — such as analyzing QRadar offenses with OpenAI — making them easy to run, modify, and integrate into incident response workflows.

## Table of Contents

- [QRadar Offense Analyzer with OpenAI](#qradar-offense-analyzer-with-openai)
- [QRadar Offense to JIRA Issue](#qradar-offense-to-jira-issue)
- [QRadar Rule Properties Extractor](#qradar-rule-properties-extractor)


## [QRadar Offense Analyzer with OpenAI](scripts/qradar/offensetoopenai.py)

This Python script fetches a QRadar offense, extracts related rules and events, and submits them to OpenAI's Assistants API (v2) for automated analysis.

The assistant evaluates the incident, determines if it is a true/false positive, summarizes what happened, and recommends remediation actions.

### Features

- Connects to QRadar via its REST API
- Downloads offense metadata, rules, and events
- Uploads artifacts to OpenAI's file API
- Uses OpenAI Assistants v2 for contextual analysis
- Automatically cleans up assistant and thread sessions

### Requirements

- Python 3.7+
- Internet access (for OpenAI API)
- Access to a QRadar instance with Ariel Search and rule export enabled

No third-party libraries are required — only the Python standard library is used.

### Setup

#### Environment Variables

Set the following environment variables before running the script:

```bash
export QRADAR_KEY="your_qradar_token"
export QRADAR_BASE_URL="https://your-qradar-url/api"

export OPENAI_TOKEN="your_openai_api_key"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

### Usage
```bash
python offensetoopenai.py --offense-id 12345
```

### Example Output
```bash
INFO [main] Collecting offense info...
INFO Downloading rules...
INFO Processing rules...
INFO Downloading events...
INFO Uploading rules.json...
INFO Uploading events.json...
INFO Creating Assistant...
...
user: Given rules.json and events.json...
assistant: This appears to be a false positive due to ...
```
---
---
## [QRadar Offense to JIRA Issue](scripts/qradar/offensetojira.py)

This Python script retrieves an offense from IBM QRadar and creates a corresponding JIRA issue with a structured description of the incident. It helps streamline incident response workflows by integrating SIEM detection with JIRA ticketing system.

### Features

- Connects to **QRadar** via its REST API
- Retrieves offense metadata, including type, source, domain, and log sources
- Creates a **JIRA issue** automatically with all offense details
- Uses **standard Python only** — no third-party dependencies
- Secure: uses environment variables for all credentials

### Requirements

- Python 3.7+
- QRadar instance with offense API access
- JIRA Cloud or Server with API token access enabled

### Setup

#### Set Environment Variables

Before running the script, export the following environment variables:

```bash
# QRadar Configuration
export QRADAR_KEY="your_qradar_api_token"
export QRADAR_BASE_URL="https://your.qradar.instance/api"

# JIRA Configuration
export JIRA_API_TOKEN="your_jira_api_token"
export JIRA_EMAIL="you@example.com"
export JIRA_BASE_URL="https://yourcompany.atlassian.net"
```

### Usage

Run the script from the command line:
```bash
python offensetojira.py \
  --offense-id 12345 \
  --jira-project SEC \
  --jira-issue-type Task
```
### Example output:
```bash
2024-06-10 14:55:12 [INFO] Collecting offense info for offense id 12345...
2024-06-10 14:55:13 [INFO] Offense info for offense id 12345 successfully collected
2024-06-10 14:55:13 [INFO] Creating jira issue...
2024-06-10 14:55:14 [INFO] Jira issue SEC-456 successfully created.
```
---
---
## [QRadar Rule Properties Extractor](scripts/qradar/ruleinfo.py)
This script connects to a QRadar instance, downloads all **custom detection rules**, parses them from the system export XML, and exports structured metadata (e.g., name, type, owner, creation date, logic) to a **TSV file**.

It’s a fast, portable, dependency-free way to generate reports or audits of QRadar detection logic.

---

## Features

- Connects to QRadar via the REST API (`/config/extension_management`)
- Triggers a custom rules export task and polls for completion
- Extracts and parses rules from the exported ZIP archive
- Outputs a clean `.tsv` file with detailed metadata:
  - Rule name, type, owner, creation/modification dates, enable status, offense type, and test logic
- Uses only standard Python libraries — no external dependencies

---

## Requirements

- Python 3.7 or higher
- QRadar API token with permissions to export content and list rule metadata

---

## Setup

### 1. Environment Variables

Set the following environment variables before running:

```bash
export QRADAR_KEY="your_qradar_api_token"
export QRADAR_BASE_URL="https://your.qradar.instance/api"