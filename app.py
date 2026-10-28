"""
Sentinel AI - AI Security Engineer Chatbot (Phase 1)
=====================================================
A defensive AI security engineer chat application powered by Groq and Streamlit.
Adheres strictly to defensive security best practices, zero-execution sandboxing,
and modular design.
"""

import os
import time
import re
import streamlit as st
from dotenv import load_dotenv
import groq

# ------------------------------------------------------------------------------
# 1. Environment & Configuration
# ------------------------------------------------------------------------------
load_dotenv()

DEFAULT_MODEL = "qwen/qwen3.8-27b"
SUPPORTED_MODELS = [
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "allam-2-7b",
]
DEFAULT_MAX_LENGTH = 4000
DEFAULT_SYSTEM_PROMPT = (
    "You are Sentinel AI, an AI Security Engineer assistant. Your mission is to "
    "provide expert guidance on defensive cybersecurity, application security, "
    "threat modeling (STRIDE/PASTA), OWASP Top 10 (Web & LLM), vulnerability remediation, "
    "and secure code architecture.\n\n"
    "Core Principles:\n"
    "1. Adhere strictly to ethical security guidelines.\n"
    "2. Provide defensive, educational, and remediation advice.\n"
    "3. Never generate offensive exploits, malware, or assist in unauthorized attacks.\n"
    "4. Maintain a clear, professional, and rigorous engineering tone."
)


def load_configuration() -> dict:
    """
    Load application configuration from environment variables with safe defaults.
    Never exposes or logs the raw API key.
    """
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    model = os.getenv("GROQ_MODEL", DEFAULT_MODEL).strip()
    if not model:
        model = DEFAULT_MODEL

    try:
        max_length = int(os.getenv("MAX_MESSAGE_LENGTH", str(DEFAULT_MAX_LENGTH)))
    except ValueError:
        max_length = DEFAULT_MAX_LENGTH

    system_prompt = os.getenv("DEFAULT_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT).strip()
    if not system_prompt:
        system_prompt = DEFAULT_SYSTEM_PROMPT

    return {
        "api_key": api_key,
        "model": model,
        "max_length": max_length,
        "system_prompt": system_prompt,
    }


# ------------------------------------------------------------------------------
# 2. Input Validation & Security Guardrails
# ------------------------------------------------------------------------------
def validate_user_input(content: str, max_length: int = DEFAULT_MAX_LENGTH) -> tuple[bool, str | None]:
    """
    Validate user prompt before forwarding to Groq API.
    - Prevents empty or whitespace-only messages.
    - Enforces configurable character limits.
    - Rejects null bytes and invalid control sequences.
    
    Returns:
        tuple[bool, str | None]: (is_valid, error_message)
    """
    if not isinstance(content, str):
        return False, "Message must be a text string."

    stripped = content.strip()
    if not stripped:
        return False, "Message cannot be empty or contain only whitespace."

    if len(content) > max_length:
        return (
            False,
            f"Message length ({len(content)} characters) exceeds the maximum allowed limit of {max_length} characters.",
        )

    if "\x00" in content:
        return False, "Message contains invalid null-byte control characters."

    return True, None


def build_api_messages(
    system_prompt: str,
    chat_history: list[dict],
    new_user_message: str | None = None,
) -> list[dict]:
    """
    Construct the message array payload for the Groq completions endpoint.
    Places the system prompt at the root, followed by sanitized conversation history.
    """
    formatted_messages = [{"role": "system", "content": system_prompt.strip()}]

    for msg in chat_history:
        role = msg.get("role")
        content = msg.get("content", "")
        if role in ("user", "assistant") and content:
            formatted_messages.append({"role": role, "content": content})

    if new_user_message:
        formatted_messages.append({"role": "user", "content": new_user_message.strip()})

    return formatted_messages


# ------------------------------------------------------------------------------
# 3. Groq SDK Client & API Handler
# ------------------------------------------------------------------------------
def create_groq_client(api_key: str | None = None) -> groq.Groq:
    """
    Instantiate the official Groq client.
    Raises ValueError if the API key is missing or blank.
    """
    key = api_key if api_key is not None else os.getenv("GROQ_API_KEY", "")
    key = key.strip() if isinstance(key, str) else ""

    if not key:
        raise ValueError(
            "GROQ_API_KEY is not configured. Please define it in your .env file or terminal environment."
        )

    return groq.Groq(api_key=key)


def fetch_available_models(client: groq.Groq | None = None) -> list[str]:
    """
    Query Groq Cloud API for active chat models accessible to this account.
    Filters out audio (whisper) and classification-only models.
    Falls back gracefully to verified default models if offline or client is unavailable.
    """
    if not client:
        return list(SUPPORTED_MODELS)

    try:
        models_data = client.models.list()
        active = [
            m.id
            for m in models_data.data
            if not m.id.startswith("whisper")
            and "prompt-guard" not in m.id
            and "orpheus" not in m.id
        ]
        if active:
            # Sort with DEFAULT_MODEL first if present
            sorted_models = sorted(active)
            if DEFAULT_MODEL in sorted_models:
                sorted_models.remove(DEFAULT_MODEL)
                sorted_models.insert(0, DEFAULT_MODEL)
            return sorted_models
        return list(SUPPORTED_MODELS)
    except Exception:
        return list(SUPPORTED_MODELS)


def get_groq_completion(
    client: groq.Groq,
    messages: list[dict],
    model: str = DEFAULT_MODEL,
    temperature: float = 0.7,
    max_tokens: int = 1024,
    max_retries: int = 2,
    retry_delay: float = 2.0,
) -> str:
    """
    Execute chat completion via Groq SDK with robust error handling and exponential backoff retry.
    Automatically retries transient RateLimitErrors.
    Catches specific exceptions and returns user-friendly messages without leaking secrets.
    """
    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            if not response.choices:
                return "No response choice returned by the model."

            msg = response.choices[0].message
            content = msg.content or ""
            # Handle reasoning models that output thoughts in reasoning attribute
            if not content and hasattr(msg, "reasoning") and msg.reasoning:
                content = msg.reasoning

            return content or "No response content returned by the model."
        except groq.AuthenticationError:
            return "⚠️ Authentication Error: Invalid or expired Groq API Key. Please verify your GROQ_API_KEY."
        except groq.RateLimitError as exc:
            # If we still have retries remaining, wait and retry
            if attempt < max_retries:
                wait_time = retry_delay * (attempt + 1)
                match = re.search(r"try again in ([\d\.]+)s", str(exc))
                if match:
                    try:
                        wait_time = min(float(match.group(1)) + 0.5, 6.0)
                    except ValueError:
                        pass
                time.sleep(wait_time)
                continue

            # Retries exhausted; provide actionable guidance
            wait_hint = "a few seconds"
            match = re.search(r"try again in ([\d\.]+s?)", str(exc))
            if match:
                wait_hint = match.group(1)

            return (
                f"⚠️ Rate Limit: Groq's tokens-per-minute limit was reached. "
                f"Please wait {wait_hint} before trying again, or decrease 'Max Output Tokens' / clear history in the sidebar."
            )
        except groq.APIConnectionError:
            return "⚠️ Network Error: Unable to establish a connection with Groq Cloud. Please check your network."
        except groq.APIStatusError as exc:
            if exc.status_code == 404:
                return (
                    f"⚠️ Groq API Error (Status 404): The model '{model}' does not exist or is unavailable on your tier. "
                    f"Please switch to an active model such as 'qwen/qwen3.8-27b' or 'openai/gpt-oss-120b' from the sidebar."
                )
            return f"⚠️ Groq API Error (Status {exc.status_code}): {exc.message}"
        except Exception as exc:
            return f"⚠️ Unexpected Error: An error occurred while communicating with the model: {str(exc)}"

    return "⚠️ Rate limit retry limit reached. Please wait a moment and try again."


# ------------------------------------------------------------------------------
# 4. Streamlit UI & Custom Red/White Gradient Aesthetic
# ------------------------------------------------------------------------------
def inject_custom_css():
    """Inject modern red-and-white gradient cyber aesthetic."""
    st.markdown(
        """
        <style>
        /* Import clean modern typography */
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

        html, body, [class*="css"] {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        /* Subtle dark gradient canvas */
        .stApp {
            background: radial-gradient(circle at 10% 20%, rgba(255, 30, 68, 0.08) 0%, transparent 40%),
                        radial-gradient(circle at 90% 80%, rgba(180, 0, 30, 0.06) 0%, transparent 45%),
                        #0B0C10;
            color: #F5F6FA;
        }

        /* Custom Header Hero */
        .hero-banner {
            background: linear-gradient(135deg, rgba(30, 10, 16, 0.75) 0%, rgba(18, 20, 28, 0.85) 100%);
            border: 1px solid rgba(255, 30, 68, 0.25);
            border-radius: 16px;
            padding: 24px 28px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px -10px rgba(255, 30, 68, 0.2);
            backdrop-filter: blur(12px);
        }

        .hero-title {
            font-size: 2.1rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin: 0;
            background: linear-gradient(90deg, #FFFFFF 0%, #FFA8B5 45%, #FF2A4D 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .hero-subtitle {
            font-size: 0.95rem;
            color: #C0C5D0;
            margin-top: 8px;
            margin-bottom: 14px;
            font-weight: 400;
        }

        .pill-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.76rem;
            font-weight: 600;
            letter-spacing: 0.02em;
            text-transform: uppercase;
        }

        .pill-red {
            background: rgba(255, 30, 68, 0.15);
            color: #FF5A78;
            border: 1px solid rgba(255, 30, 68, 0.35);
        }

        .pill-white {
            background: rgba(255, 255, 255, 0.08);
            color: #FFFFFF;
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .pill-green {
            background: rgba(46, 213, 115, 0.12);
            color: #2ED573;
            border: 1px solid rgba(46, 213, 115, 0.3);
        }

        .pill-amber {
            background: rgba(255, 171, 0, 0.12);
            color: #FFAB00;
            border: 1px solid rgba(255, 171, 0, 0.3);
        }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background: #11131B;
            border-right: 1px solid rgba(255, 30, 68, 0.15);
        }

        /* Chat Message Styling */
        div[data-testid="stChatMessage"] {
            border-radius: 14px;
            padding: 16px 18px;
            margin-bottom: 12px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(8px);
        }

        /* User Message Accent */
        div[data-testid="stChatMessage"]:has(span[data-testid="chatAvatarIcon-user"]) {
            background: linear-gradient(135deg, rgba(255, 30, 68, 0.12) 0%, rgba(35, 15, 22, 0.5) 100%);
            border-left: 3px solid #FF1E44;
        }

        /* Assistant Message Accent */
        div[data-testid="stChatMessage"]:has(span[data-testid="chatAvatarIcon-assistant"]) {
            background: rgba(22, 25, 36, 0.65);
            border-left: 3px solid #FFFFFF;
        }

        /* Streamlit Input field glow */
        .stChatInputContainer textarea {
            border: 1px solid rgba(255, 30, 68, 0.3) !important;
            border-radius: 12px !important;
            background: #12141D !important;
            color: #FFFFFF !important;
        }
        .stChatInputContainer textarea:focus {
            border-color: #FF1E44 !important;
            box-shadow: 0 0 12px rgba(255, 30, 68, 0.35) !important;
        }

        /* Buttons */
        .stButton>button {
            border-radius: 10px;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        .stButton>button:hover {
            transform: translateY(-1px);
            border-color: #FF1E44;
            color: #FF1E44;
        }

        /* Code block font */
        code, pre {
            font-family: 'JetBrains Mono', monospace !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header(api_configured: bool, current_model: str):
    """Render top hero banner with badge pills and security status."""
    status_pill = (
        '<span class="pill pill-green">● Groq API Connected</span>'
        if api_configured
        else '<span class="pill pill-amber">○ Missing API Key (.env)</span>'
    )

    st.markdown(
        f"""
        <div class="hero-banner">
            <h1 class="hero-title">
                <span>🛡️ Sentinel AI</span>
            </h1>
            <div class="hero-subtitle">
                Defensive AI Security Engineer Portfolio &bull; Phase 1 Sandboxed Advisory Interface
            </div>
            <div class="pill-container">
                {status_pill}
                <span class="pill pill-red">⚡ Groq: {current_model}</span>
                <span class="pill pill-white">🔒 Zero Tool/Code Execution</span>
                <span class="pill pill-white">🛡️ Defensive Engineering</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar(config: dict, client: groq.Groq | None = None) -> tuple[str, str, float, int]:
    """
    Render sidebar configuration controls.
    Returns:
        tuple: (selected_model, active_system_prompt, temperature, max_tokens)
    """
    st.sidebar.markdown("### ⚙️ Engine Parameters")

    # Dynamic or cached model discovery
    if "available_models" not in st.session_state or not st.session_state.available_models:
        st.session_state.available_models = fetch_available_models(client)

    available_models = list(st.session_state.available_models)
    configured_model = config.get("model", DEFAULT_MODEL)
    if configured_model and configured_model not in available_models:
        available_models.insert(0, configured_model)

    default_index = 0
    if configured_model in available_models:
        default_index = available_models.index(configured_model)

    selected_model = st.sidebar.selectbox(
        "Groq Model",
        options=available_models,
        index=default_index,
        help="Active model selected for chat completions via Groq Cloud.",
    )

    temperature = st.sidebar.slider(
        "Temperature",
        min_value=0.0,
        max_value=1.0,
        value=0.7,
        step=0.05,
        help="Higher values produce more creative output; lower values make answers more deterministic.",
    )

    max_tokens = st.sidebar.slider(
        "Max Output Tokens",
        min_value=256,
        max_value=4096,
        value=1024,
        step=128,
        help="Maximum number of tokens to generate in a single response.",
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🛡️ System Prompt Guardrails")

    if "custom_system_prompt" not in st.session_state:
        st.session_state.custom_system_prompt = config["system_prompt"]

    active_system_prompt = st.sidebar.text_area(
        "Configurable System Prompt",
        value=st.session_state.custom_system_prompt,
        height=180,
        help="Guides the persona, ethical constraints, and defensive domain expertise of the assistant.",
    )

    if st.sidebar.button("🔄 Reset System Prompt", use_container_width=True):
        st.session_state.custom_system_prompt = config["system_prompt"]
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔒 Security Posture")
    st.sidebar.caption(
        "• **Execution Sandbox:** Active (Pure text input/output; no command execution or tool execution).\n"
        "• **Secret Isolation:** Key loaded from environment; never logged or exposed in UI.\n"
        f"• **Input Limit:** {config['max_length']} characters per message."
    )

    if st.sidebar.button("🗑️ Clear Conversation", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    return selected_model, active_system_prompt, temperature, max_tokens


def render_prompt_suggestions():
    """Render one-click sample defensive security questions for new conversations."""
    st.markdown("##### 💡 Example Security Inquiries")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🛡️ STRIDE threat model for an API Gateway", use_container_width=True):
            return "Provide a STRIDE threat modeling breakdown for an internet-facing API Gateway handling JWT tokens."
        if st.button("⚠️ OWASP Top 10 for LLM Applications", use_container_width=True):
            return "Explain the top 3 risks in the OWASP Top 10 for Large Language Model Applications and how to mitigate them."
    with col2:
        if st.button("🔍 Secure code review checklist in Python", use_container_width=True):
            return "What are the essential items to look for during a defensive secure code review of a Python Flask application?"
        if st.button("🔐 Defense-in-depth against Prompt Injections", use_container_width=True):
            return "What architectural layers provide effective defense-in-depth against prompt injection vulnerabilities?"
    return None


# ------------------------------------------------------------------------------
# 5. Main Application Flow
# ------------------------------------------------------------------------------
def main():
    st.set_page_config(
        page_title="Sentinel AI - Security Chatbot",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_custom_css()
    config = load_configuration()

    # Initialize Session History
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Check API Key Status & Client Instantiation
    api_configured = bool(config["api_key"])
    active_client = None
    if api_configured:
        try:
            active_client = create_groq_client(config["api_key"])
        except Exception:
            active_client = None

    selected_model, system_prompt, temperature, max_tokens = render_sidebar(
        config, client=active_client
    )

    render_header(api_configured=api_configured, current_model=selected_model)

    # Missing API Key Warning Banner with Setup Guidance
    if not api_configured:
        st.warning(
            "🔑 **GROQ_API_KEY is not detected.**\n\n"
            "To chat with Sentinel AI, set your Groq API key in your terminal or create a `.env` file:\n"
            "```bash\n"
            "export GROQ_API_KEY=\"gsk_your_actual_key_here\"\n"
            "streamlit run app.py\n"
            "```\n"
            "*Note: For security reasons, never paste your actual API key into shared prompts or version control.*"
        )

    # Render Chat History
    for message in st.session_state.messages:
        role = message["role"]
        avatar = "👤" if role == "user" else "🛡️"
        with st.chat_message(role, avatar=avatar):
            st.markdown(message["content"])

    # Sample Prompts if conversation is empty
    suggested_prompt = None
    if not st.session_state.messages:
        suggested_prompt = render_prompt_suggestions()

    # User Input Handling
    user_input = st.chat_input(
        f"Ask a defensive security question (max {config['max_length']} chars)..."
    )

    prompt_to_process = user_input or suggested_prompt

    if prompt_to_process:
        # Step 1: Input Validation
        is_valid, validation_error = validate_user_input(
            prompt_to_process, max_length=config["max_length"]
        )

        if not is_valid:
            st.error(f"❌ Input Validation Error: {validation_error}")
            return

        # Step 2: Ensure API key is configured
        if not api_configured:
            st.error(
                "❌ Cannot submit request: GROQ_API_KEY is missing. Please configure it in your environment."
            )
            return

        # Step 3: Record and render user message
        st.session_state.messages.append({"role": "user", "content": prompt_to_process})
        with st.chat_message("user", avatar="👤"):
            st.markdown(prompt_to_process)

        # Step 4: Call Groq API securely
        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("Analyzing with defensive security guidelines..."):
                try:
                    client = create_groq_client(config["api_key"])
                    payload = build_api_messages(
                        system_prompt=system_prompt,
                        chat_history=st.session_state.messages[:-1],
                        new_user_message=prompt_to_process,
                    )
                    response_text = get_groq_completion(
                        client=client,
                        messages=payload,
                        model=selected_model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                except Exception as exc:
                    response_text = f"⚠️ Client initialization failure: {str(exc)}"

                st.markdown(response_text)

        # Step 5: Save assistant response to conversation history
        st.session_state.messages.append(
            {"role": "assistant", "content": response_text}
        )


if __name__ == "__main__":
    main()
