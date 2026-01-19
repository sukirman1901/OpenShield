"""
AI Client Factory
Creates the appropriate AI client based on configuration
"""

from typing import Dict, Any, Union
from ai.gemini_client import GeminiClient
from ai.openai_client import OpenAIClient


def create_client(config: Dict[str, Any]) -> Union[GeminiClient, OpenAIClient]:
    """
    Create an AI client based on configuration

    Args:
        config: Application configuration

    Returns:
        Instantiated AI client
    """
    ai_config = config.get("ai", {})
    provider = ai_config.get("provider", "gemini").lower()

    if provider == "gemini":
        return GeminiClient(config)
    elif provider in ["openai", "cliproxy"]:
        return OpenAIClient(config)
    else:
        raise ValueError(f"Unsupported AI provider: {provider}")
