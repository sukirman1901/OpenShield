"""
Google Dorking tool for discovering vulnerable targets
Uses multiple search engines and techniques to find potentially vulnerable websites
"""

import re
import asyncio
import random
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

from tools.base_tool import BaseTool


# Common Google Dorks for finding vulnerable targets
DORK_CATEGORIES = {
    "sql_injection": [
        'inurl:".php?id="',
        'inurl:".php?cat="',
        'inurl:".php?page="',
        'inurl:".asp?id="',
        'inurl:"index.php?id="',
        'inurl:"product.php?id="',
        'inurl:"news.php?id="',
        'inurl:"article.php?id="',
        'inurl:"view.php?id="',
        'inurl:"item.php?id="',
    ],
    "login_pages": [
        'intitle:"login" inurl:admin',
        'intitle:"admin login"',
        'inurl:"/admin/login"',
        'inurl:"/administrator"',
        'inurl:"wp-login.php"',
        'inurl:"/user/login"',
        'intitle:"dashboard" inurl:login',
    ],
    "exposed_files": [
        'filetype:sql "insert into"',
        'filetype:log "password"',
        'filetype:env "DB_PASSWORD"',
        'filetype:conf "password"',
        'intitle:"index of" "backup"',
        'intitle:"index of" ".git"',
        'intitle:"index of" "config"',
        'filetype:bak inurl:"config"',
    ],
    "sensitive_dirs": [
        'intitle:"index of" /admin',
        'intitle:"index of" /backup',
        'intitle:"index of" /private',
        'intitle:"index of" /.git',
        'intitle:"index of" /uploads',
        'inurl:"/phpmyadmin"',
        'inurl:"/server-status"',
    ],
    "wordpress": [
        'inurl:"/wp-content/plugins/"',
        'inurl:"/wp-includes/"',
        'inurl:"wp-config.php.bak"',
        'intitle:"WordPress" inurl:readme.html',
        '"powered by wordpress" inurl:wp-admin',
    ],
    "cameras_iot": [
        'intitle:"webcamXP 5"',
        'inurl:"/view/view.shtml"',
        'intitle:"Live View / - AXIS"',
        'inurl:"MultiCameraFrame?Mode="',
        'intitle:"Network Camera"',
    ],
    "error_pages": [
        '"sql syntax" "mysql"',
        '"ORA-" "error"',
        '"PostgreSQL" "ERROR"',
        '"Warning: mysql_" "on line"',
        '"Fatal error:" "on line"',
        'intext:"Unclosed quotation mark"',
    ],
    "api_keys": [
        'intext:"api_key" filetype:json',
        'intext:"apikey" filetype:env',
        'intext:"secret_key" filetype:py',
        'intext:"AWS_SECRET" filetype:env',
        '"Authorization: Bearer" filetype:log',
    ],
}

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


@dataclass
class DorkResult:
    """Result from a dork search"""

    url: str
    title: str
    snippet: str
    dork: str
    category: str


class DorkingTool(BaseTool):
    """Google Dorking tool for target discovery"""

    def __init__(self, config):
        # Don't call super().__init__ as there's no CLI tool
        self.config = config
        self.tool_name = "dorking"
        self.is_available = True  # Always available (Python-only)

        from utils.logger import get_logger

        self.logger = get_logger(config)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Not used - Python only tool"""
        return ["echo", "Google Dorking (Python)"]

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Not used - Python only tool"""
        return {}

    async def execute(self, target: str = "", **kwargs) -> Dict[str, Any]:
        """
        Execute Google dorking

        Args:
            target: Optional domain to restrict search (e.g., "site:example.com")
            **kwargs:
                category: Specific dork category (sql_injection, login_pages, etc.)
                dork: Custom dork query
                max_results: Maximum results to return (default 20)
                use_browser: Use Playwright browser for more reliable results
        """
        start_time = datetime.now()

        category = kwargs.get("category", "sql_injection")
        custom_dork = kwargs.get("dork")
        max_results = kwargs.get("max_results", 20)
        use_browser = kwargs.get("use_browser", True)  # Default to browser

        results: List[DorkResult] = []

        # Build dork queries
        if custom_dork:
            dorks = [(custom_dork, "custom")]
        elif category == "all":
            dorks = []
            for cat, cat_dorks in DORK_CATEGORIES.items():
                for d in cat_dorks[:3]:  # Limit per category
                    dorks.append((d, cat))
        else:
            cat_dorks = DORK_CATEGORIES.get(category, DORK_CATEGORIES["sql_injection"])
            dorks = [(d, category) for d in cat_dorks]

        # Add site restriction if target provided
        if target:
            dorks = [(f"site:{target} {d}", cat) for d, cat in dorks]

        # Search using Playwright browser (most reliable)
        if use_browser:
            for dork, cat in dorks[:5]:  # Limit to avoid detection
                try:
                    browser_results = await self._search_with_browser(dork)
                    for r in browser_results:
                        results.append(
                            DorkResult(
                                url=r["url"],
                                title=r["title"],
                                snippet=r["snippet"],
                                dork=dork,
                                category=cat,
                            )
                        )

                    # Add delay between searches
                    await asyncio.sleep(random.uniform(2.0, 4.0))

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    self.logger.warning(f"Browser search failed for '{dork}': {e}")
                    continue
        else:
            # Fallback to HTTP-based search
            for dork, cat in dorks[:10]:
                try:
                    ddg_results = await self._search_duckduckgo_html(dork)
                    for r in ddg_results:
                        results.append(
                            DorkResult(
                                url=r["url"],
                                title=r["title"],
                                snippet=r["snippet"],
                                dork=dork,
                                category=cat,
                            )
                        )

                    await asyncio.sleep(random.uniform(1.0, 2.0))

                    if len(results) >= max_results:
                        break

                except Exception as e:
                    self.logger.warning(f"Dork search failed for '{dork}': {e}")
                    continue

        duration = (datetime.now() - start_time).total_seconds()

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for r in results:
            if r.url not in seen_urls:
                seen_urls.add(r.url)
                unique_results.append(r)

        # Limit results
        unique_results = unique_results[:max_results]

        # Build parsed output
        parsed = {
            "results": [
                {
                    "url": r.url,
                    "title": r.title,
                    "snippet": r.snippet,
                    "dork": r.dork,
                    "category": r.category,
                }
                for r in unique_results
            ],
            "count": len(unique_results),
            "dorks_used": list(set(r.dork for r in unique_results)),
            "categories": list(set(r.category for r in unique_results)),
        }

        # Build human-readable output
        output_lines = [
            f"Google Dorking Results",
            f"Category: {category}",
            f"Found {len(unique_results)} potential targets in {duration:.2f}s",
            "",
            "=" * 60,
        ]

        for i, r in enumerate(unique_results, 1):
            output_lines.append(f"\n[{i}] {r.title}")
            output_lines.append(f"    URL: {r.url}")
            output_lines.append(f"    Category: {r.category}")
            if r.snippet:
                snippet = r.snippet[:100] + "..." if len(r.snippet) > 100 else r.snippet
                output_lines.append(f"    Snippet: {snippet}")

        raw_output = "\n".join(output_lines)

        return {
            "tool": self.tool_name,
            "target": target or "global",
            "command": f"dorking(category={category})",
            "exit_code": 0,
            "duration": duration,
            "timestamp": start_time.isoformat(),
            "raw_output": raw_output,
            "error": None,
            "parsed": parsed,
        }

    async def _search_with_browser(self, query: str) -> List[Dict[str, str]]:
        """Search using Playwright browser for reliable results"""
        try:
            from playwright.async_api import async_playwright

            # Try to import stealth, but don't fail if missing
            try:
                from playwright_stealth import Stealth
            except ImportError:
                Stealth = None
                self.logger.warning("playwright-stealth not found, running without stealth mode")
        except ImportError:
            self.logger.warning("Playwright not installed, falling back to HTTP")
            return await self._search_duckduckgo_html(query)

        results = []

        async with async_playwright() as p:
            try:
                # Use Firefox (less detection)
                browser = await p.firefox.launch(headless=True)
            except Exception as e:
                self.logger.warning(f"Failed to launch browser: {e}. Falling back to HTTP.")
                return await self._search_duckduckgo_html(query)

            context = await browser.new_context(
                user_agent=random.choice(USER_AGENTS),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
            )
            page = await context.new_page()

            try:
                # Apply stealth if available
                try:
                    stealth = Stealth()
                    await stealth.apply_stealth_async(page)
                except Exception:
                    pass

                # Use Startpage (privacy-focused, less bot detection)
                encoded_query = urllib.parse.quote(query)
                url = f"https://www.startpage.com/sp/search?query={encoded_query}"

                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(2000)

                # Extract results from Startpage
                result_elements = await page.query_selector_all(".w-gl__result")

                for elem in result_elements[:15]:
                    try:
                        link_elem = await elem.query_selector("a.w-gl__result-title")
                        if link_elem:
                            href = await link_elem.get_attribute("href")
                            title = await link_elem.inner_text()

                            # Get snippet
                            snippet_elem = await elem.query_selector(".w-gl__description")
                            snippet = await snippet_elem.inner_text() if snippet_elem else ""

                            if href and href.startswith("http"):
                                results.append(
                                    {
                                        "url": href,
                                        "title": title.strip(),
                                        "snippet": snippet.strip(),
                                    }
                                )
                    except Exception:
                        continue

                # If Startpage fails, try Brave Search
                if not results:
                    url = f"https://search.brave.com/search?q={encoded_query}"
                    await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    await page.wait_for_timeout(2000)

                    result_elements = await page.query_selector_all(".snippet")

                    for elem in result_elements[:15]:
                        try:
                            link_elem = await elem.query_selector("a.result-header")
                            if link_elem:
                                href = await link_elem.get_attribute("href")
                                title = await link_elem.inner_text()

                                snippet_elem = await elem.query_selector(".snippet-description")
                                snippet = await snippet_elem.inner_text() if snippet_elem else ""

                                if href and href.startswith("http"):
                                    results.append(
                                        {
                                            "url": href,
                                            "title": title.strip(),
                                            "snippet": snippet.strip(),
                                        }
                                    )
                        except Exception:
                            continue

            except Exception as e:
                self.logger.warning(f"Browser search error: {e}")
            finally:
                await browser.close()

        return results

    async def _search_duckduckgo_html(self, query: str) -> List[Dict[str, str]]:
        """Search DuckDuckGo HTML version (no API key needed)"""
        import httpx

        results = []

        encoded_query = urllib.parse.quote(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}"

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)

            if response.status_code not in [200, 202]:
                self.logger.warning(
                    f"DuckDuckGo returned {response.status_code}, trying fallback..."
                )
                return await self._search_searxng(query)

            html = response.text

            # Parse results using regex (avoid BeautifulSoup dependency)
            # DuckDuckGo HTML format: <a class="result__a" href="...">title</a>
            # and <a class="result__snippet">snippet</a>

            # Try multiple patterns for different DDG versions
            result_patterns = [
                r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)</a>',
                r'<a[^>]*href="([^"]*)"[^>]*class="result__a"[^>]*>([^<]*)</a>',
                r'class="result__url"[^>]*href="([^"]*)"[^>]*>',
            ]

            urls_titles = []
            for pattern in result_patterns:
                matches = re.findall(pattern, html)
                if matches:
                    urls_titles = matches
                    break

            # If no results, try SearXNG as fallback
            if not urls_titles:
                return await self._search_searxng(query)

            snippet_pattern = r'<a[^>]*class="result__snippet"[^>]*>([^<]*)</a>'
            snippets = re.findall(snippet_pattern, html)

            for i, match in enumerate(urls_titles):
                if isinstance(match, tuple):
                    url, title = match[0], match[1] if len(match) > 1 else ""
                else:
                    url, title = match, ""

                # DuckDuckGo uses redirect URLs, extract actual URL
                if "uddg=" in url:
                    actual_url_match = re.search(r"uddg=([^&]+)", url)
                    if actual_url_match:
                        url = urllib.parse.unquote(actual_url_match.group(1))

                snippet = snippets[i] if i < len(snippets) else ""

                # Clean up
                title = re.sub(r"<[^>]+>", "", str(title)).strip()
                snippet = re.sub(r"<[^>]+>", "", str(snippet)).strip()

                if url.startswith("http"):
                    results.append(
                        {
                            "url": url,
                            "title": title,
                            "snippet": snippet,
                        }
                    )

        return results

    async def _search_searxng(self, query: str) -> List[Dict[str, str]]:
        """Search using public SearXNG instances"""
        import httpx

        results = []

        # Public SearXNG instances
        searxng_instances = [
            "https://searx.be",
            "https://search.bus-hit.me",
            "https://searx.tiekoetter.com",
            "https://search.sapti.me",
        ]

        encoded_query = urllib.parse.quote(query)

        for instance in searxng_instances:
            try:
                url = f"{instance}/search?q={encoded_query}&format=json"

                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "application/json",
                }

                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    response = await client.get(url, headers=headers)

                    if response.status_code == 200:
                        data = response.json()

                        for item in data.get("results", []):
                            results.append(
                                {
                                    "url": item.get("url", ""),
                                    "title": item.get("title", ""),
                                    "snippet": item.get("content", ""),
                                }
                            )

                        if results:
                            return results

            except Exception:
                continue

        # If SearXNG fails, try Bing
        return await self._search_bing(query)

    async def _search_bing(self, query: str) -> List[Dict[str, str]]:
        """Search Bing (backup method)"""
        import httpx

        results = []

        encoded_query = urllib.parse.quote(query)
        url = f"https://www.bing.com/search?q={encoded_query}"

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                response = await client.get(url, headers=headers)

                if response.status_code != 200:
                    return results

                html = response.text

                # Parse Bing results
                # Try multiple patterns as Bing structure changes
                result_patterns = [
                    # Standard: <h2><a href="...">Title</a></h2>
                    r'<h[23][^>]*>\s*<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>\s*</h[23]>',
                    # Alternative: <li class="b_algo">...<a href="...">...</a>
                    r'class="b_algo"[^>]*>.*?<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                    # Generic fallback
                    r'<a[^>]*href="(https?://[^"]+)"[^>]*><h2>([^<]*)</h2></a>',
                ]

                matches = []
                for pattern in result_patterns:
                    found = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
                    if found:
                        matches.extend(found)

                # Remove duplicates and process
                seen_urls = set()

                for url, title in matches:
                    # Clean title
                    title = re.sub(r"<[^>]+>", "", title).strip()

                    if url not in seen_urls and not any(
                        x in url for x in ["bing.com", "microsoft.com", "msn.com", "go.microsoft"]
                    ):
                        seen_urls.add(url)
                        results.append(
                            {
                                "url": url,
                                "title": title,
                                "snippet": "",
                            }
                        )
        except Exception:
            pass

        return results


# Convenience function for direct use
async def run_dorking(
    config: Dict, category: str = "sql_injection", target: str = "", max_results: int = 20
) -> Dict[str, Any]:
    """Run dorking and return results"""
    tool = DorkingTool(config)
    return await tool.execute(target, category=category, max_results=max_results)
