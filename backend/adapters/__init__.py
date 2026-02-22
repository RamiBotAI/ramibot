from .base import BaseAdapter
from .openai_adapter import OpenAIAdapter
from .anthropic_adapter import AnthropicAdapter
from .openrouter_adapter import OpenRouterAdapter
from .lmstudio_adapter import LMStudioAdapter
from .ollama_adapter import OllamaAdapter

ADAPTERS = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "openrouter": OpenRouterAdapter,
    "lmstudio": LMStudioAdapter,
    "ollama": OllamaAdapter,
}

__all__ = ["BaseAdapter", "ADAPTERS", "OpenAIAdapter", "AnthropicAdapter",
           "OpenRouterAdapter", "LMStudioAdapter", "OllamaAdapter"]
