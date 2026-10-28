# Sentinel AI - AI Security Engineer Chatbot (Phase 1)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B.svg)](https://streamlit.io/)
[![Groq SDK](https://img.shields.io/badge/Groq-Official%20SDK-f55036.svg)](https://console.groq.com/)
[![Tests Passing](https://img.shields.io/badge/Tests-31%20Passed-brightgreen.svg)](#running-automated-tests)
[![Security Sandbox](https://img.shields.io/badge/Sandbox-Zero%20Code%20Execution-red.svg)](#security-architecture--guardrails)

> **Phase 1 of AI Security Engineer Portfolio Project**  
> A clean, modern, defensive AI security chatbot interface powered by Groq and Streamlit, featuring a cyber-themed red/white gradient aesthetic, strict zero-code execution sandboxing, input validation, and comprehensive automated test suites.

---

## 📑 Table of Contents
- [Architecture Overview](#architecture-overview)
- [Security Architecture & Guardrails](#security-architecture--guardrails)
- [Repository File Structure](#repository-file-structure)
- [Ubuntu Setup & Installation Guide](#ubuntu-setup--installation-guide)
- [Secure API Key Configuration](#secure-api-key-configuration)
- [Running the Application](#running-the-application)
- [Running Automated Tests](#running-automated-tests)
- [Project Roadmap (Phase 2 Preview)](#project-roadmap-phase-2-preview)

---

## 🏛️ Architecture Overview

The application follows a modular, defensive architecture separating configuration, input validation, SDK communication, and presentation layers:

```mermaid
graph TD
    User([User / Browser]) <-->|Chat Input / Session State| UI[Streamlit UI & Red/White Gradient Engine]
    
    subgraph Core Defensive Layer
        UI -->|Raw Input String| Val[Input Validation & Sanitization]
        Val -->|Boundary Checks & Null-byte Filter| SafeMsg[Sanitized Message Payload]
        SafeMsg --> MsgBuilder[API Message Builder]
        SysConfig[Configurable Defensive System Prompt] --> MsgBuilder
    end
    
    subgraph Security Isolation Sandbox
        MsgBuilder -->|Strict Text Prompt| GroqClient[Groq Python SDK Client]
        EnvSecrets[(Environment Variables / .env)] -.->|GROQ_API_KEY / GROQ_MODEL| GroqClient
        GroqClient <-->|HTTPS API / LPU Inference| GroqCloud[(Groq Cloud API)]
    end
    
    subgraph Zero-Execution Enforcement
        GroqCloud -.->|Text Response Only| UI
        NoExec[❌ No eval / No exec / No os.system / No Subprocess]
    end
```

### Key Modules in `app.py`:
1. **`load_configuration()`**: Safely loads environment parameters (`GROQ_API_KEY`, `GROQ_MODEL`, `MAX_MESSAGE_LENGTH`, `DEFAULT_SYSTEM_PROMPT`). Never prints or leaks secrets.
2. **`validate_user_input()`**: Rejects empty prompts, enforces maximum length constraints (default: 4000 chars), and filters out null-byte control characters.
3. **`build_api_messages()`**: Structures conversation history with the system prompt at the root and strips invalid roles.
4. **`create_groq_client()`**: Instantiates the official `groq.Groq` client safely.
5. **`get_groq_completion()`**: Handles chat completions with structured exception handling (`AuthenticationError`, `RateLimitError`, `APIConnectionError`).
6. **`inject_custom_css()` & UI Components**: Renders a sleek obsidian-dark canvas with a glowing ruby-crimson gradient mesh, glassmorphism cards, and badge indicators.

---

## 🔒 Security Architecture & Guardrails

As a defensive AI security engineer portfolio piece, the system adheres to strict security principles:

1. **Zero-Code Execution Sandbox**:
   - The chatbot strictly processes text prompts and returns text responses.
   - At no point are user inputs or model responses routed to `eval()`, `exec()`, `os.system()`, `subprocess`, or any dynamic code execution engine.
   - Verified by automated security test cases in [`tests/test_app.py`](file:///home/abul-hassan/projects/ai-security-chatbot/tests/test_app.py).

2. **Secret Hygiene & Isolation**:
   - API keys are retrieved from environment variables (`GROQ_API_KEY`) via `python-dotenv`.
   - `.env` is explicitly ignored by [`.gitignore`](file:///home/abul-hassan/projects/ai-security-chatbot/.gitignore) to eliminate credential leakage risk.
   - The UI displays an anonymous boolean status indicator (`● API Connected` / `○ Missing API Key`) without exposing the actual key.

3. **Input Sanitization & Length Boundaries**:
   - Configurable character limits (default: 4000 characters) mitigate Denial of Service (DoS) and context window exhaustion attacks.
   - Null-byte detection prevents string truncation vulnerabilities.

4. **Defensive AI System Prompt**:
   - The default system prompt directs the LLM to focus on defensive engineering, STRIDE threat modeling, and OWASP Top 10 remediation while strictly prohibiting exploit generation.
   - The system prompt is configurable in the sidebar and can be reset instantly.

---

## 📂 Repository File Structure

```
ai-security-chatbot/
├── .env.example              # Template for environment variables (copy to .env)
├── .gitignore                # Excludes secrets (.env), virtualenvs (.venv), caches
├── .streamlit/
│   └── config.toml           # Streamlit theme configuration (crimson/dark palette)
├── app.py                    # Main application: UI, config, validation, Groq client
├── requirements.txt          # Python dependencies
├── README.md                 # Complete documentation and setup guide
└── tests/
    ├── __init__.py           # Test package indicator
    └── test_app.py           # Automated unit & integration tests (mocked Groq SDK)
```

---

## 🐧 Ubuntu Setup & Installation Guide

Follow these steps to set up and run the project on Ubuntu (tested on Ubuntu 22.04 / 24.04 LTS):

### 1. Prerequisites
Ensure Python 3.10+ and pip are installed:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

### 2. Clone or Navigate to the Workspace
```bash
cd /home/abul-hassan/projects/ai-security-chatbot
```

### 3. Create and Activate Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🔑 Secure API Key Configuration

> [!IMPORTANT]
> **Never commit your `.env` file or paste your actual Groq API key into public chat prompts or version control.**

You can configure your Groq API key in either of two secure ways:

### Option A: Local `.env` File (Recommended for Local Dev)
1. Copy the provided `.env.example` template to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` in your preferred editor (e.g., `nano .env` or `vim .env`):
   ```bash
   nano .env
   ```
3. Replace the placeholder with your actual Groq API key:
   ```ini
   GROQ_API_KEY=gsk_your_actual_key_here
   GROQ_MODEL=qwen/qwen3.8-27b
   ```
4. Save and close the file (`Ctrl+O`, `Enter`, `Ctrl+X` in nano).

### Option B: Terminal Environment Variable (Recommended for Ephemeral Sessions)
Export the variable directly in your terminal before launching the application:
```bash
export GROQ_API_KEY="gsk_your_actual_key_here"
```

To verify the variable is set without printing the secret key:
```bash
[ -n "$GROQ_API_KEY" ] && echo "GROQ_API_KEY is configured" || echo "GROQ_API_KEY is NOT set"
```

---

## 🚀 Running the Application

Once your virtual environment is active and your API key is configured:

```bash
streamlit run app.py
```

The application will start and provide a local URL:
```
Local URL: http://localhost:8501
Network URL: http://<your-ip>:8501
```

Open `http://localhost:8501` in your web browser to interact with Sentinel AI.

---

## 🧪 Running Automated Tests

The test suite in [`tests/test_app.py`](file:///home/abul-hassan/projects/ai-security-chatbot/tests/test_app.py) uses `unittest.mock` to mock all Groq API calls. **Tests run offline, consume 0 API credits, and do not require a valid API key.**

Run tests using pytest:
```bash
# Ensure virtual environment is active
source .venv/bin/activate

# Execute pytest with verbose output
pytest -v
```

### Test Coverage Highlights:
- **Input Validation**: Null-byte injection, empty prompts, whitespace prompts, max length boundary checks.
- **Message Formatting**: Multi-turn history formatting, system prompt placement, sanitization.
- **Client Factory**: Missing key error handling, whitespace key validation, SDK instantiation.
- **Mocked Completions**: Successful generation, empty choices, `AuthenticationError`, `RateLimitError`, `APIConnectionError`.
- **Security Sandboxing**: Verifies that adversarial prompts (`eval`, `exec`, `os.system`, `; cat /etc/passwd`, `<script>`) remain inert strings and never trigger shell or OS execution.

---

## 🗺️ Project Roadmap (Phase 2 Preview)

- [x] **Phase 1 (Current)**: Core Chatbot with Groq SDK, Streamlit UI, red/white gradient theme, defensive guardrails, input validation, automated mocked tests.
- [ ] **Phase 2 (Upcoming)**: Automated Prompt Injection Testing Framework (Direct Injection, Indirect Injection, Jailbreaking evaluation, automated security scorecards).
