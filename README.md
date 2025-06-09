# Sec Ops One Shots

Sec Ops One Shots is a collection of standalone, self-contained Python scripts for automating common tasks in security operations. Each script focuses on one specific function — such as analyzing QRadar offenses with OpenAI — making them easy to run, modify, and integrate into incident response workflows.

## Table of Contents

- [QRadar Offense Analyzer with OpenAI](#qradar-offense-analyzer-with-openai)


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