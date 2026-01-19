"""
OpenAI API client for Guardian (supports Cliproxy)
Handles communication with OpenAI-compatible AI models via LangChain
"""

import os
import time
import asyncio
from typing import Optional, Dict, Any
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from dotenv import load_dotenv

from utils.logger import get_logger


class OpenAIClient:
    """OpenAI API client wrapper (compatible with Cliproxy)"""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        # Get API configuration
        ai_config = config.get("ai", {})

        # API Key
        self.api_key = ai_config.get("api_key") or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            # Fallback for Cliproxy specific env var if needed
            self.api_key = os.getenv("CLIPROXY_API_KEY")

        if not self.api_key:
            # For local proxy, we might allow no key or dummy
            self.logger.warning("No API key found, using 'sk-dummy' for local proxy compatibility")
            self.api_key = "sk-dummy"

        # Base URL for Cliproxy
        self.base_url = ai_config.get("base_url") or os.getenv("OPENAI_API_BASE")
        
        # Load available models from config or use defaults
        self.available_models = ai_config.get("available_models", [
            {"id": "gemini-3-flash-preview", "name": "Gemini 3 Flash"},
            {"id": "gpt-4-turbo", "name": "GPT-4 Turbo"},
        ])

        self.model_name = ai_config.get("model", self.available_models[0]["id"])
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 4000)

        # Rate limiting: requests per minute
        self.rate_limit = ai_config.get("rate_limit", 60)
        self._min_request_interval = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
        self._last_request_time = 0.0

        try:
            self._init_llm()

            base_url_msg = f" (base_url: {self.base_url})" if self.base_url else ""
            self.logger.info(f"Initialized OpenAI client: {self.model_name}{base_url_msg}")
        except Exception as e:
            self.logger.error(f"Failed to initialize OpenAI client: {e}")
            raise

    def _init_llm(self):
        """Initialize the LLM instance"""
        self.llm = ChatOpenAI(
            model=self.model_name,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

    def list_models(self) -> list[dict]:
        """List available models from config"""
        return self.available_models

    def set_model(self, model_id: str):
        """Switch current model"""
        self.model_name = model_id
        self._init_llm()
        self.logger.info(f"Switched model to: {model_id}")

    def get_current_model(self) -> dict:
        """Get current model info"""
        return {"id": self.model_name, "name": self.model_name}

    async def _apply_rate_limit(self):
        """Apply rate limiting between API calls"""
        if self._min_request_interval > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                wait_time = self._min_request_interval - elapsed
                self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s before next request")
                await asyncio.sleep(wait_time)
        self._last_request_time = time.time()

    def _apply_rate_limit_sync(self):
        """Synchronous rate limiting"""
        if self._min_request_interval > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._min_request_interval:
                wait_time = self._min_request_interval - elapsed
                self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s before next request")
                time.sleep(wait_time)
        self._last_request_time = time.time()

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        """
        Generate a response from OpenAI/Cliproxy
        """
        try:
            await self._apply_rate_limit()

            messages = []

            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))

            if context:
                messages.extend(context)

            messages.append(HumanMessage(content=prompt))

            response = await self.llm.ainvoke(messages)

            return response.content

        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            raise

    def generate_sync(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        """Synchronous version of generate"""
        try:
            self._apply_rate_limit_sync()

            messages = []

            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))

            if context:
                messages.extend(context)

            messages.append(HumanMessage(content=prompt))

            response = self.llm.invoke(messages)
            return response.content

        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            raise

    async def generate_with_reasoning(
        self, prompt: str, system_prompt: str, context: Optional[list] = None
    ) -> Dict[str, str]:
        """
        Generate response with explicit reasoning
        """
        # Enhanced prompt to extract reasoning
        enhanced_prompt = f"""{prompt}

Please structure your response as:
1. REASONING: Explain your thought process and decision-making
2. RESPONSE: Provide your final answer or recommendation
"""

        response = await self.generate(enhanced_prompt, system_prompt, context)

        # Parse reasoning and response
        parts = {"reasoning": "", "response": ""}

        if "REASONING:" in response and "RESPONSE:" in response:
            try:
                reasoning_start = response.find("REASONING:") + len("REASONING:")
                response_start = response.find("RESPONSE:")

                parts["reasoning"] = response[reasoning_start:response_start].strip()
                parts["response"] = response[response_start + len("RESPONSE:") :].strip()
            except Exception:
                # Fallback if parsing fails
                parts["response"] = response
                parts["reasoning"] = "Parsing error, see response"
        else:
            # If not properly formatted, put everything in response
            parts["response"] = response
            parts["reasoning"] = "No explicit reasoning provided"

        return parts
