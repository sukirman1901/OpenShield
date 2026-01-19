"""
Exa MCP Client - Integration with Exa.ai Search
Enables the agent to perform deep semantic searches for vulnerabilities and exploits.
"""

import os
import httpx
from typing import Dict, Any, List, Optional
from utils.logger import get_logger

class ExaClient:
    """Client for interacting with Exa.ai API (Search & Retrieve)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.api_key = os.getenv("EXA_API_KEY") 
        self.base_url = "https://api.exa.ai"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "x-api-key": self.api_key # Support both auth styles if needed
        }

    async def search(self, query: str, num_results: int = 5, use_autoprompt: bool = True, start_published_date: str = None) -> List[Dict[str, Any]]:
        """
        Perform a semantic search using Exa.
        
        Args:
            query: The search query string.
            num_results: Number of results to return.
            use_autoprompt: Whether to let Exa optimize the query.
            start_published_date: Filter for recent exploits (ISO 8601 string).
            
        Returns:
            List of search results with contents/highlights.
        """
        if not self.api_key:
            self.logger.warning("Exa API Key not found. Skipping semantic search.")
            return []

        url = f"{self.base_url}/search"
        
        # Payload optimized for Research Agent needs
        payload = {
            "query": query,
            "numResults": num_results,
            "useAutoprompt": use_autoprompt,
            "contents": {
                "text": True,  # Get full text for analysis
                "highlights": {"numSentences": 3},  # Get key snippets
            }
        }
        
        if start_published_date:
            payload["startPublishedDate"] = start_published_date

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=self.headers, timeout=30.0)
                response.raise_for_status()
                data = response.json()
                return data.get("results", [])
        except Exception as e:
            self.logger.error(f"Exa search failed: {e}")
            return []

    async def get_contents(self, ids: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieve full contents for specific result IDs.
        """
        if not self.api_key:
            return []
            
        url = f"{self.base_url}/contents"
        payload = {"ids": ids}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=self.headers, timeout=30.0)
                response.raise_for_status()
                data = response.json()
                return data.get("results", [])
        except Exception as e:
            self.logger.error(f"Exa content retrieval failed: {e}")
            return []
