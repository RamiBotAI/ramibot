import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from adapters.openai_adapter import OpenAIAdapter
from adapters.anthropic_adapter import AnthropicAdapter
from adapters.openrouter_adapter import OpenRouterAdapter
from adapters.lmstudio_adapter import LMStudioAdapter
from adapters.ollama_adapter import OllamaAdapter


@pytest.mark.anyio
async def test_openai_capabilities():
    adapter = OpenAIAdapter(api_key="test-key")
    caps = await adapter.capabilities()
    assert caps["streaming"] is True
    assert caps["tool_calling"] is True
    assert caps["reasoning"] is True


@pytest.mark.anyio
async def test_anthropic_capabilities():
    adapter = AnthropicAdapter(api_key="test-key")
    caps = await adapter.capabilities()
    assert caps["streaming"] is True
    assert caps["tool_calling"] is True
    assert caps["reasoning"] is True


@pytest.mark.anyio
async def test_openrouter_capabilities():
    adapter = OpenRouterAdapter(api_key="test-key")
    caps = await adapter.capabilities()
    assert caps["streaming"] is True
    assert caps["tool_calling"] is True
    assert caps["reasoning"] is False


@pytest.mark.anyio
async def test_lmstudio_capabilities():
    adapter = LMStudioAdapter()
    caps = await adapter.capabilities()
    assert caps["streaming"] is True
    assert caps["tool_calling"] is False
    assert caps["reasoning"] is False


@pytest.mark.anyio
async def test_ollama_capabilities():
    adapter = OllamaAdapter()
    caps = await adapter.capabilities()
    assert caps["streaming"] is True
    assert caps["tool_calling"] is False
    assert caps["reasoning"] is False


@pytest.mark.anyio
async def test_anthropic_list_models():
    adapter = AnthropicAdapter(api_key="test-key")
    models = await adapter.list_models()
    assert len(models) == 3
    ids = [m["id"] for m in models]
    assert "claude-sonnet-4-20250514" in ids
    assert "claude-haiku-4-20250414" in ids
    assert "claude-opus-4-20250514" in ids


@pytest.mark.anyio
async def test_openai_list_models():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {"id": "gpt-4o", "object": "model"},
            {"id": "gpt-3.5-turbo", "object": "model"},
            {"id": "dall-e-3", "object": "model"},
            {"id": "o1-mini", "object": "model"},
        ]
    }
    mock_response.raise_for_status = MagicMock()

    adapter = OpenAIAdapter(api_key="test-key")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
        models = await adapter.list_models()

    ids = [m["id"] for m in models]
    assert "gpt-4o" in ids
    assert "gpt-3.5-turbo" in ids
    assert "o1-mini" in ids
    assert "dall-e-3" not in ids


@pytest.mark.anyio
async def test_ollama_list_models():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [
            {"name": "llama3:latest"},
            {"name": "mistral:latest"},
        ]
    }
    mock_response.raise_for_status = MagicMock()

    adapter = OllamaAdapter()
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
        models = await adapter.list_models()

    assert len(models) == 2
    assert models[0]["id"] == "llama3:latest"
    assert models[1]["id"] == "mistral:latest"


@pytest.mark.anyio
async def test_openai_adapter_provider_name():
    adapter = OpenAIAdapter(api_key="test")
    assert adapter.provider_name == "openai"


@pytest.mark.anyio
async def test_anthropic_adapter_provider_name():
    adapter = AnthropicAdapter(api_key="test")
    assert adapter.provider_name == "anthropic"


@pytest.mark.anyio
async def test_openrouter_adapter_provider_name():
    adapter = OpenRouterAdapter(api_key="test")
    assert adapter.provider_name == "openrouter"


@pytest.mark.anyio
async def test_lmstudio_adapter_provider_name():
    adapter = LMStudioAdapter()
    assert adapter.provider_name == "lmstudio"


@pytest.mark.anyio
async def test_ollama_adapter_provider_name():
    adapter = OllamaAdapter()
    assert adapter.provider_name == "ollama"
