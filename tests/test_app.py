"""
Unit and Integration Tests for Sentinel AI Chatbot (Phase 1)
Uses unittest.mock to mock all Groq API calls (offline, 0 credits used).
"""

from unittest.mock import MagicMock, patch
import pytest
import groq
import httpx

from app import (
    load_configuration,
    validate_user_input,
    build_api_messages,
    create_groq_client,
    get_groq_completion,
    fetch_available_models,
    SUPPORTED_MODELS,
    DEFAULT_MODEL,
    DEFAULT_MAX_LENGTH,
    DEFAULT_SYSTEM_PROMPT,
)


class TestInputValidation:
    def test_valid_input_passes(self):
        valid_message = "What is the STRIDE threat modeling framework?"
        is_valid, error = validate_user_input(valid_message, max_length=500)
        assert is_valid is True
        assert error is None

    def test_empty_string_fails(self):
        is_valid, error = validate_user_input("", max_length=500)
        assert is_valid is False
        assert "empty or contain only whitespace" in error

    def test_whitespace_only_fails(self):
        is_valid, error = validate_user_input("   \t \n  ", max_length=500)
        assert is_valid is False
        assert "empty or contain only whitespace" in error

    def test_exceeding_max_length_fails(self):
        max_len = 100
        oversized = "A" * (max_len + 1)
        is_valid, error = validate_user_input(oversized, max_length=max_len)
        assert is_valid is False
        assert f"exceeds the maximum allowed limit of {max_len}" in error

    def test_exact_max_length_boundary_passes(self):
        max_len = 100
        exact_text = "A" * max_len
        is_valid, error = validate_user_input(exact_text, max_length=max_len)
        assert is_valid is True
        assert error is None

    def test_non_string_input_fails(self):
        is_valid, error = validate_user_input(12345, max_length=500)  # type: ignore
        assert is_valid is False
        assert "must be a text string" in error

    def test_null_byte_fails(self):
        malformed = "Normal text with a null byte \x00 attack"
        is_valid, error = validate_user_input(malformed, max_length=500)
        assert is_valid is False
        assert "null-byte" in error


class TestMessageFormatting:
    def test_build_api_messages_with_system_and_user(self):
        sys_prompt = "You are a defensive AI security bot."
        user_msg = "How do I secure an AWS S3 bucket?"
        messages = build_api_messages(
            system_prompt=sys_prompt,
            chat_history=[],
            new_user_message=user_msg,
        )
        assert len(messages) == 2
        assert messages[0] == {"role": "system", "content": sys_prompt}
        assert messages[1] == {"role": "user", "content": user_msg}

    def test_build_api_messages_with_history(self):
        sys_prompt = "Defense bot"
        history = [
            {"role": "user", "content": "Question 1"},
            {"role": "assistant", "content": "Answer 1"},
        ]
        new_prompt = "Question 2"
        messages = build_api_messages(
            system_prompt=sys_prompt,
            chat_history=history,
            new_user_message=new_prompt,
        )
        assert len(messages) == 4
        assert messages[0] == {"role": "system", "content": sys_prompt}
        assert messages[1] == {"role": "user", "content": "Question 1"}
        assert messages[2] == {"role": "assistant", "content": "Answer 1"}
        assert messages[3] == {"role": "user", "content": "Question 2"}

    def test_build_api_messages_filters_invalid_roles_and_empty_content(self):
        sys_prompt = "Defense bot"
        corrupted_history = [
            {"role": "unknown_role", "content": "Bad"},
            {"role": "user", "content": ""},
            {"role": "user", "content": "Valid question"},
        ]
        messages = build_api_messages(
            system_prompt=sys_prompt,
            chat_history=corrupted_history,
        )
        assert len(messages) == 2
        assert messages[0] == {"role": "system", "content": sys_prompt}
        assert messages[1] == {"role": "user", "content": "Valid question"}


class TestConfigurationAndClient:
    def test_load_configuration_defaults(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        monkeypatch.delenv("GROQ_MODEL", raising=False)
        monkeypatch.delenv("MAX_MESSAGE_LENGTH", raising=False)
        monkeypatch.delenv("DEFAULT_SYSTEM_PROMPT", raising=False)

        cfg = load_configuration()
        assert cfg["api_key"] == ""
        assert cfg["model"] == DEFAULT_MODEL
        assert cfg["max_length"] == DEFAULT_MAX_LENGTH
        assert cfg["system_prompt"] == DEFAULT_SYSTEM_PROMPT

    def test_load_configuration_custom_env(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test_fake_key_12345")
        monkeypatch.setenv("GROQ_MODEL", "llama-3.1-8b-instant")
        monkeypatch.setenv("MAX_MESSAGE_LENGTH", "2500")
        monkeypatch.setenv("DEFAULT_SYSTEM_PROMPT", "Custom defensive prompt")

        cfg = load_configuration()
        assert cfg["api_key"] == "gsk_test_fake_key_12345"
        assert cfg["model"] == "llama-3.1-8b-instant"
        assert cfg["max_length"] == 2500
        assert cfg["system_prompt"] == "Custom defensive prompt"

    def test_create_groq_client_with_valid_key(self):
        client = create_groq_client(api_key="gsk_valid_mock_key_1234567890")
        assert isinstance(client, groq.Groq)

    def test_create_groq_client_missing_key_raises_value_error(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        with pytest.raises(ValueError, match="GROQ_API_KEY is not configured"):
            create_groq_client(api_key="")

    def test_create_groq_client_whitespace_key_raises_value_error(self):
        with pytest.raises(ValueError, match="GROQ_API_KEY is not configured"):
            create_groq_client(api_key="   ")


class TestGroqCompletionsMocked:
    def test_get_groq_completion_success(self):
        mock_choice = MagicMock()
        mock_choice.message.content = "SQL injection can be mitigated using prepared statements."
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        messages = [{"role": "user", "content": "How do I prevent SQL injection?"}]
        result = get_groq_completion(
            client=mock_client,
            messages=messages,
            model="llama-3.3-70b-versatile",
            temperature=0.7,
            max_tokens=1024,
        )

        assert "SQL injection can be mitigated using prepared statements." in result
        mock_client.chat.completions.create.assert_called_once_with(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.7,
            max_tokens=1024,
        )

    def test_get_groq_completion_empty_choices(self):
        mock_response = MagicMock()
        mock_response.choices = []

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        result = get_groq_completion(client=mock_client, messages=[])
        assert "No response choice returned" in result

    def test_get_groq_completion_auth_error(self):
        http_response = httpx.Response(
            status_code=401,
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )
        auth_err = groq.AuthenticationError(
            message="Invalid API Key provided",
            response=http_response,
            body={"error": {"message": "Invalid API Key provided"}},
        )

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = auth_err

        result = get_groq_completion(client=mock_client, messages=[])
        assert "Authentication Error" in result
        assert "Invalid or expired Groq API Key" in result

    def test_get_groq_completion_rate_limit_error(self):
        http_response = httpx.Response(
            status_code=429,
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )
        rate_err = groq.RateLimitError(
            message="Rate limit reached",
            response=http_response,
            body={"error": {"message": "Rate limit reached"}},
        )

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = rate_err

        result = get_groq_completion(client=mock_client, messages=[], max_retries=0)
        assert "Rate Limit" in result

    def test_get_groq_completion_rate_limit_retry_succeeds(self):
        http_response = httpx.Response(
            status_code=429,
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )
        rate_err = groq.RateLimitError(
            message="Please try again in 0.1s",
            response=http_response,
            body={"error": {"message": "Please try again in 0.1s"}},
        )

        mock_choice = MagicMock()
        mock_choice.message.content = "Retried answer successfully."
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [rate_err, mock_response]

        result = get_groq_completion(
            client=mock_client,
            messages=[],
            max_retries=1,
            retry_delay=0.01,
        )
        assert result == "Retried answer successfully."
        assert mock_client.chat.completions.create.call_count == 2

    def test_get_groq_completion_network_error(self):
        conn_err = groq.APIConnectionError(
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
        )

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = conn_err

        result = get_groq_completion(client=mock_client, messages=[])
        assert "Network Error" in result
        assert "Unable to establish a connection with Groq Cloud" in result

    def test_get_groq_completion_404_model_not_found(self):
        http_response = httpx.Response(
            status_code=404,
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )
        not_found_err = groq.APIStatusError(
            message="The model llama-3.3-70b-versatile does not exist",
            response=http_response,
            body={"error": {"message": "The model llama-3.3-70b-versatile does not exist"}},
        )

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = not_found_err

        result = get_groq_completion(client=mock_client, messages=[], model="llama-3.3-70b-versatile")
        assert "Status 404" in result
        assert "does not exist or is unavailable" in result
        assert "Please switch to an active model" in result

    def test_get_groq_completion_reasoning_fallback(self):
        mock_choice = MagicMock()
        mock_choice.message.content = ""
        mock_choice.message.reasoning = "Detailed defensive security reasoning."
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        result = get_groq_completion(client=mock_client, messages=[])
        assert result == "Detailed defensive security reasoning."

    def test_fetch_available_models_without_client(self):
        models = fetch_available_models(client=None)
        assert models == list(SUPPORTED_MODELS)

    def test_fetch_available_models_with_mocked_client(self):
        mock_m1 = MagicMock()
        mock_m1.id = "qwen/qwen3.8-27b"
        mock_m2 = MagicMock()
        mock_m2.id = "whisper-large-v3"
        mock_m3 = MagicMock()
        mock_m3.id = "openai/gpt-oss-120b"
        mock_models_response = MagicMock()
        mock_models_response.data = [mock_m1, mock_m2, mock_m3]

        mock_client = MagicMock()
        mock_client.models.list.return_value = mock_models_response

        models = fetch_available_models(client=mock_client)
        assert "qwen/qwen3.8-27b" in models
        assert "openai/gpt-oss-120b" in models
        assert "whisper-large-v3" not in models


class TestSecuritySandboxing:
    @pytest.mark.parametrize(
        "adversarial_prompt",
        [
            "__import__('os').system('ls -la')",
            "eval('2 + 2')",
            "exec(\"import subprocess; subprocess.run(['echo', 'hacked'])\")",
            "; cat /etc/passwd",
            "`whoami`",
            "$(id)",
            "<script>alert('xss')</script>",
        ],
    )
    def test_messages_remain_inert_and_never_invoke_execution(self, adversarial_prompt):
        with patch("os.system") as mock_os_system, \
             patch("subprocess.run") as mock_subproc_run, \
             patch("subprocess.Popen") as mock_subproc_popen:

            is_valid, _ = validate_user_input(adversarial_prompt, max_length=500)
            assert is_valid is True

            formatted = build_api_messages("System", [], adversarial_prompt)
            assert formatted[-1]["content"] == adversarial_prompt

            mock_os_system.assert_not_called()
            mock_subproc_run.assert_not_called()
            mock_subproc_popen.assert_not_called()
