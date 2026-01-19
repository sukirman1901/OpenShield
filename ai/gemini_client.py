"""
Google Gemini API client for Guardian
Handles communication with Gemini AI model via LangChain
"""

import os
import time
import asyncio
from typing import Optional, Dict, Any
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from dotenv import load_dotenv

from utils.logger import get_logger


class GeminiClient:
    """Google Gemini API client wrapper"""

    def __init__(self, config: Dict[str, Any]):
        load_dotenv()

        self.config = config
        self.logger = get_logger(config)

        # Get API key from environment
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                "GOOGLE_API_KEY not found in environment. "
                "Please set it in .env file or environment variables."
            )

        # Initialize Gemini model via LangChain
        ai_config = config.get("ai", {})
        self.model_name = ai_config.get("model", "gemini-2.5-pro")
        self.temperature = ai_config.get("temperature", 0.2)
        self.max_tokens = ai_config.get("max_tokens", 8000)

        # Rate limiting: requests per minute
        self.rate_limit = ai_config.get("rate_limit", 60)  # Default 60 RPM
        self._min_request_interval = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
        self._last_request_time = 0.0

        try:
            self.llm = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=api_key,
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
                convert_system_message_to_human=True,
            )
            self.logger.info(
                f"Initialized Gemini model: {self.model_name} (rate limit: {self.rate_limit} RPM)"
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Gemini client: {e}")
            raise

    def list_models(self) -> list[dict]:
        """List available Gemini models"""
        return [
            {"id": "gemini-2.5-pro", "name": "Gemini 2.5 Pro"},
            {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro"},
            {"id": "gemini-1.0-pro", "name": "Gemini 1.0 Pro"},
        ]

    def set_model(self, model_id: str):
        """Switch current model"""
        self.model_name = model_id
        try:
            api_key = os.getenv("GOOGLE_API_KEY")
            self.llm = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=api_key,
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
                convert_system_message_to_human=True,
            )
            self.logger.info(f"Switched Gemini model to: {self.model_name}")
        except Exception as e:
            self.logger.error(f"Failed to switch Gemini model: {e}")

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
        Generate a response from Gemini

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for instructions
            context: Optional conversation history

        Returns:
            Generated response text
        """
        try:
            # Apply rate limiting
            await self._apply_rate_limit()

            messages = []

            # Add system prompt if provided
            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))

            # Add context if provided
            if context:
                messages.extend(context)

            # Add current prompt
            messages.append(HumanMessage(content=prompt))

            # Generate response
            response = await self.llm.ainvoke(messages)

            return response.content

        except Exception as e:
            self.logger.error(f"Gemini API error: {e}")
            raise

    def generate_sync(
        self, prompt: str, system_prompt: Optional[str] = None, context: Optional[list] = None
    ) -> str:
        """Synchronous version of generate"""
        try:
            # Apply rate limiting
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
            self.logger.error(f"Gemini API error: {e}")
            raise

    async def generate_with_reasoning(
        self, prompt: str, system_prompt: str, context: Optional[list] = None
    ) -> Dict[str, str]:
        """
        Generate response with explicit reasoning

        Returns:
            Dict with 'reasoning' and 'response' keys
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
            reasoning_start = response.find("REASONING:") + len("REASONING:")
            response_start = response.find("RESPONSE:") + len("RESPONSE:")

            parts["reasoning"] = response[reasoning_start : response.find("RESPONSE:")].strip()
            parts["response"] = response[response_start:].strip()
        else:
            # If not properly formatted, put everything in response
            parts["response"] = response
            parts["reasoning"] = "No explicit reasoning provided"

        return parts
