"""
Browser Agent - Web Crawling & Dynamic Analysis
Uses Playwright for browser automation and vulnerability detection
"""

import asyncio
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
import re

from playwright.async_api import async_playwright, Browser, Page, BrowserContext
from bs4 import BeautifulSoup

from core.agent import BaseAgent
from core.memory import Finding
from utils.logger import get_logger


class BrowserAgent(BaseAgent):
    """Agent that performs browser-based web analysis and vulnerability detection"""

    def __init__(self, config, gemini_client, memory):
        super().__init__("BrowserAgent", config, gemini_client, memory)
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.screenshots_dir = (
            Path(config.get("output", {}).get("save_path", "./reports")) / "screenshots"
        )
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

        # Browser config
        self.browser_config = config.get("browser", {})
        self.headless = self.browser_config.get("headless", True)
        self.timeout = self.browser_config.get("timeout", 30000)
        self.screenshot_on_vuln = self.browser_config.get("screenshot_on_vuln", True)

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute browser-based analysis"""
        url = kwargs.get("url") or kwargs.get("target")
        if not url:
            raise ValueError("URL is required for browser analysis")

        return await self.analyze_web(url)

    async def analyze_web(self, url: str, max_depth: int = 2) -> Dict[str, Any]:
        """
        Perform comprehensive web analysis using browser automation

        Args:
            url: Target URL to analyze
            max_depth: Maximum crawl depth

        Returns:
            Dict with findings, screenshots, and analysis
        """
        self.log_action("StartingAnalysis", f"Analyzing {url}")

        async with async_playwright() as p:
            # Launch browser
            self.browser = await p.chromium.launch(headless=self.headless)
            self.context = await self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            )

            try:
                # Initial page load
                page = await self.context.new_page()
                page.set_default_timeout(self.timeout)

                # Navigate to URL
                self.logger.info(f"Navigating to {url}")
                response = await page.goto(url, wait_until="networkidle")

                # Store initial response for later use
                self._initial_response = response

                # Take screenshot
                screenshot_path = await self._take_screenshot(page, "homepage")

                # Extract page info
                page_info = await self._extract_page_info(page)

                # Detect vulnerabilities
                findings = []

                # 1. Check for XSS vulnerabilities
                xss_findings = await self._detect_xss(page, url)
                findings.extend(xss_findings)

                # 2. Check for sensitive data exposure
                sensitive_findings = await self._detect_sensitive_data(page)
                findings.extend(sensitive_findings)

                # 3. Check for security headers
                header_findings = await self._check_security_headers(page)
                findings.extend(header_findings)

                # 4. Crawl and analyze forms
                form_findings = await self._analyze_forms(page, url)
                findings.extend(form_findings)

                # 5. Check for DOM-based issues
                dom_findings = await self._detect_dom_issues(page)
                findings.extend(dom_findings)

                # Add findings to memory (if memory is available)
                if self.memory:
                    for finding in findings:
                        self.memory.add_finding(finding)

                self.log_action("AnalysisComplete", f"Found {len(findings)} issues")

                return {
                    "url": url,
                    "findings": findings,
                    "page_info": page_info,
                    "screenshot": str(screenshot_path),
                    "total_findings": len(findings),
                }

            finally:
                await self.browser.close()

    async def _take_screenshot(self, page: Page, name: str) -> Path:
        """Take screenshot of current page"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_path = self.screenshots_dir / f"{name}_{timestamp}.png"
        await page.screenshot(path=str(screenshot_path), full_page=True)
        self.logger.info(f"Screenshot saved: {screenshot_path}")
        return screenshot_path

    async def _extract_page_info(self, page: Page) -> Dict[str, Any]:
        """Extract basic page information"""
        title = await page.title()
        url = page.url

        # Get all links
        links = await page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")

        # Get all forms
        forms = await page.eval_on_selector_all(
            "form",
            """
            forms => forms.map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                    name: i.name,
                    type: i.type
                }))
            }))
        """,
        )

        # Get cookies
        cookies = await page.context.cookies()

        return {
            "title": title,
            "url": url,
            "links_count": len(links),
            "forms_count": len(forms),
            "cookies_count": len(cookies),
            "forms": forms,
        }

    async def _detect_xss(self, page: Page, base_url: str) -> List[Finding]:
        """Detect XSS vulnerabilities by testing input fields"""
        findings = []

        # XSS test payloads
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            '"><script>alert(1)</script>',
        ]

        # Find all input fields
        inputs = await page.query_selector_all("input[type='text'], input[type='search'], textarea")

        for idx, input_elem in enumerate(inputs):
            input_name = await input_elem.get_attribute("name") or f"input_{idx}"

            for payload in payloads:
                try:
                    # Fill input with payload
                    await input_elem.fill(payload)

                    # Try to submit form or trigger event
                    form = await input_elem.evaluate_handle("el => el.closest('form')")
                    if form:
                        # Check if payload is reflected in page source
                        await page.wait_for_timeout(500)
                        content = await page.content()

                        if payload in content:
                            # Potential XSS found
                            finding = Finding(
                                id=f"xss_{input_name}_{datetime.now().timestamp()}",
                                severity="high",
                                title=f"Reflected XSS in {input_name}",
                                description=f"Input field '{input_name}' reflects user input without proper sanitization",
                                evidence=f"Payload: {payload}",
                                tool="browser_agent",
                                target=base_url,
                                timestamp=datetime.now().isoformat(),
                                remediation="Implement proper input validation and output encoding",
                            )
                            findings.append(finding)

                            if self.screenshot_on_vuln:
                                await self._take_screenshot(page, f"xss_{input_name}")

                            break  # Found XSS, no need to test other payloads

                except Exception as e:
                    self.logger.debug(f"Error testing XSS on {input_name}: {e}")
                    continue

        return findings

    async def _detect_sensitive_data(self, page: Page) -> List[Finding]:
        """Detect sensitive data exposure in page content"""
        findings = []
        content = await page.content()

        # Patterns for sensitive data
        patterns = {
            "api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "password": r"password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "token": r"token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "secret": r"secret['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN (RSA |)PRIVATE KEY-----",
        }

        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                finding = Finding(
                    id=f"sensitive_{data_type}_{datetime.now().timestamp()}",
                    severity="critical",
                    title=f"Sensitive Data Exposure: {data_type}",
                    description=f"Found {len(matches)} potential {data_type} exposed in page source",
                    evidence=f"Pattern matched: {pattern}",
                    tool="browser_agent",
                    target=page.url,
                    timestamp=datetime.now().isoformat(),
                    remediation="Remove sensitive data from client-side code. Use environment variables.",
                )
                findings.append(finding)

        return findings

    async def _check_security_headers(self, page: Page) -> List[Finding]:
        """Check for missing security headers"""
        findings = []

        # Use stored response from initial navigation instead of re-navigating
        if hasattr(self, "_initial_response") and self._initial_response:
            headers = self._initial_response.headers
        else:
            # Fallback: get headers from current page (may require re-navigation)
            response = await page.goto(page.url)
            headers = response.headers if response else {}

        # Required security headers
        required_headers = {
            "x-frame-options": "Prevents clickjacking attacks",
            "x-content-type-options": "Prevents MIME type sniffing",
            "strict-transport-security": "Enforces HTTPS",
            "content-security-policy": "Prevents XSS and injection attacks",
            "x-xss-protection": "Enables XSS filter",
        }

        for header, description in required_headers.items():
            if header not in headers:
                finding = Finding(
                    id=f"header_{header}_{datetime.now().timestamp()}",
                    severity="medium",
                    title=f"Missing Security Header: {header}",
                    description=f"{description}",
                    evidence=f"Header '{header}' not found in response",
                    tool="browser_agent",
                    target=page.url,
                    timestamp=datetime.now().isoformat(),
                    remediation=f"Add '{header}' header to HTTP responses",
                )
                findings.append(finding)

        return findings

    async def _analyze_forms(self, page: Page, base_url: str) -> List[Finding]:
        """Analyze forms for security issues"""
        findings = []

        forms = await page.query_selector_all("form")

        for idx, form in enumerate(forms):
            action = await form.get_attribute("action") or ""
            method = await form.get_attribute("method") or "get"

            # Check for forms using GET with sensitive data
            if method.lower() == "get":
                inputs = await form.query_selector_all("input[type='password']")
                if inputs:
                    finding = Finding(
                        id=f"form_get_password_{idx}_{datetime.now().timestamp()}",
                        severity="high",
                        title="Password Transmitted via GET",
                        description="Form uses GET method to submit password, exposing it in URL",
                        evidence=f"Form action: {action}",
                        tool="browser_agent",
                        target=base_url,
                        timestamp=datetime.now().isoformat(),
                        remediation="Use POST method for forms containing sensitive data",
                    )
                    findings.append(finding)

            # Check for missing CSRF tokens
            csrf_input = await form.query_selector("input[name*='csrf'], input[name*='token']")
            if not csrf_input and method.lower() == "post":
                finding = Finding(
                    id=f"form_csrf_{idx}_{datetime.now().timestamp()}",
                    severity="medium",
                    title="Potential CSRF Vulnerability",
                    description="Form lacks visible CSRF token protection",
                    evidence=f"Form action: {action}, method: {method}",
                    tool="browser_agent",
                    target=base_url,
                    timestamp=datetime.now().isoformat(),
                    remediation="Implement CSRF token protection for state-changing operations",
                )
                findings.append(finding)

        return findings

    async def _detect_dom_issues(self, page: Page) -> List[Finding]:
        """Detect DOM-based vulnerabilities"""
        findings = []

        # Check for dangerous JavaScript functions
        dangerous_patterns = await page.evaluate("""
            () => {
                const patterns = [];
                const scripts = Array.from(document.scripts);
                
                for (const script of scripts) {
                    const content = script.textContent || script.innerText;
                    
                    // Check for eval()
                    if (content.includes('eval(')) {
                        patterns.push({type: 'eval', evidence: 'eval() usage detected'});
                    }
                    
                    // Check for innerHTML with user input
                    if (content.includes('innerHTML') && 
                        (content.includes('location.') || content.includes('document.URL'))) {
                        patterns.push({type: 'dom_xss', evidence: 'innerHTML with URL parameters'});
                    }
                    
                    // Check for document.write
                    if (content.includes('document.write(')) {
                        patterns.push({type: 'document_write', evidence: 'document.write() usage'});
                    }
                }
                
                return patterns;
            }
        """)

        for pattern in dangerous_patterns:
            severity = "high" if pattern["type"] == "dom_xss" else "medium"
            finding = Finding(
                id=f"dom_{pattern['type']}_{datetime.now().timestamp()}",
                severity=severity,
                title=f"DOM-based Issue: {pattern['type']}",
                description=f"Potentially dangerous JavaScript pattern detected",
                evidence=pattern["evidence"],
                tool="browser_agent",
                target=page.url,
                timestamp=datetime.now().isoformat(),
                remediation="Avoid dangerous JavaScript functions. Use safe alternatives.",
            )
            findings.append(finding)

        return findings

    async def google_dork_search(self, query: str, num_results: int = 5) -> List[Dict[str, str]]:
        """
        Perform Google Dorking using legitimate browser automation.
        WARNING: Use responsibly. Automated scraping may violate ToS.
        """
        self.log_action("Dorking", f"Searching Google for: {query}")
        results = []

        async with async_playwright() as p:
            # Use stealthier settings
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
            )
            page = await context.new_page()

            try:
                # Go to Google
                await page.goto("https://www.google.com")

                # Check for cookie consent (Eu) and accept if needed
                try:
                    await page.click("button:has-text('Accept all')", timeout=2000)
                except:
                    pass

                # Type search query
                await page.fill("textarea[name='q'], input[name='q']", query)
                await page.press("textarea[name='q'], input[name='q']", "Enter")

                await page.wait_for_load_state("networkidle")

                # Extract results
                # Google CSS selectors change often, try generic approach
                links = await page.query_selector_all("div.g a h3")

                for link in links:
                    if len(results) >= num_results:
                        break

                    # Get parent anchor
                    anchor = await link.evaluate_handle("el => el.closest('a')")
                    url = await anchor.get_attribute("href")
                    title = await link.inner_text()

                    if url and title and not url.startswith("/search"):
                        results.append({"url": url, "title": title})

                return results

            except Exception as e:
                self.logger.error(f"Dorking failed: {e}")
                return []
            finally:
                await browser.close()

    async def crawl_website(self, start_url: str, max_pages: int = 10) -> List[str]:
        # ... (rest of crawl_website code)
        """
        Crawl website and return list of discovered URLs

        Args:
            start_url: Starting URL
            max_pages: Maximum pages to crawl

        Returns:
            List of discovered URLs
        """
        visited = set()
        to_visit = [start_url]
        discovered_urls = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                while to_visit and len(visited) < max_pages:
                    url = to_visit.pop(0)

                    if url in visited:
                        continue

                    try:
                        self.logger.info(f"Crawling: {url}")
                        await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                        visited.add(url)
                        discovered_urls.append(url)

                        # Extract links
                        links = await page.eval_on_selector_all(
                            "a[href]", "elements => elements.map(e => e.href)"
                        )

                        # Filter and add new links
                        base_domain = urlparse(start_url).netloc
                        for link in links:
                            parsed = urlparse(link)
                            if parsed.netloc == base_domain and link not in visited:
                                to_visit.append(link)

                    except Exception as e:
                        self.logger.warning(f"Error crawling {url}: {e}")
                        continue

            finally:
                await browser.close()

        return discovered_urls
