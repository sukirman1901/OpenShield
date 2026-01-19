"""
Research Agent - Deep Vulnerability Research & Analysis
Uses web search and knowledge bases to enrich vulnerability findings
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import re

from core.agent import BaseAgent
from core.memory import Finding
from core.mcp.exa_client import ExaClient
from utils.logger import get_logger


class ResearchAgent(BaseAgent):
    """
    Agent that performs deep research on vulnerabilities
    
    Capabilities:
    - CVE database lookup (via Exa & AI)
    - Exploit database search (via Exa & AI)
    - Security advisory research
    - Attack pattern analysis
    - Mitigation strategy research
    """
    
    def __init__(self, config, gemini_client, memory):
        super().__init__("ResearchAgent", config, gemini_client, memory)
        
        # Research sources
        self.cve_patterns = r'CVE-\d{4}-\d{4,7}'
        self.cwe_patterns = r'CWE-\d{1,4}'
        
        # Initialize Exa Client
        self.exa_client = ExaClient(config)
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute research on a finding"""
        finding = kwargs.get("finding")
        if not finding:
            raise ValueError("Finding is required for research")
        
        return await self.research_vulnerability(finding)
    
    async def research_vulnerability(self, finding: Finding) -> Dict[str, Any]:
        """
        Perform comprehensive research on a vulnerability
        
        Args:
            finding: Security finding to research
            
        Returns:
            Dict with research results, CVEs, exploits, and mitigations
        """
        self.log_action("StartingResearch", f"Researching {finding.title}")
        
        research_results = {
            "finding_id": finding.id,
            "vulnerability_type": self._classify_vulnerability(finding),
            "cves": [],
            "cwes": [],
            "known_exploits": [],
            "attack_patterns": [],
            "mitigations": [],
            "references": [],
            "risk_analysis": {},
        }
        
        # Step 1: Classify vulnerability
        vuln_type = research_results["vulnerability_type"]
        
        # Step 2: Search for related CVEs (Enhanced with Exa)
        self.logger.info("🔍 Searching for related CVEs...")
        cves = await self._search_cves(vuln_type, finding)
        research_results["cves"] = cves
        
        # Step 3: Identify CWE categories
        self.logger.info("📚 Identifying CWE categories...")
        cwes = await self._identify_cwes(vuln_type)
        research_results["cwes"] = cwes
        
        # Step 4: Search for known exploits (Enhanced with Exa)
        self.logger.info("⚡ Searching for known exploits...")
        exploits = await self._search_exploits(vuln_type, finding)
        research_results["known_exploits"] = exploits
        
        # Step 5: Analyze attack patterns
        self.logger.info("🎯 Analyzing attack patterns...")
        patterns = await self._analyze_attack_patterns(vuln_type, finding)
        research_results["attack_patterns"] = patterns
        
        # Step 6: Research mitigations
        self.logger.info("🛡️ Researching mitigation strategies...")
        mitigations = await self._research_mitigations(vuln_type, finding)
        research_results["mitigations"] = mitigations
        
        # Step 7: Perform risk analysis
        self.logger.info("📊 Performing risk analysis...")
        risk = await self._perform_risk_analysis(finding, research_results)
        research_results["risk_analysis"] = risk
        
        # Step 8: Gather references
        research_results["references"] = self._gather_references(vuln_type)
        
        self.log_action("ResearchComplete", f"Found {len(cves)} CVEs, {len(exploits)} exploits")
        
        return research_results
    
    def _classify_vulnerability(self, finding: Finding) -> str:
        """Classify vulnerability type"""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        classifications = {
            "xss": ["xss", "cross-site scripting", "script injection"],
            "sqli": ["sql injection", "sqli", "database injection"],
            "csrf": ["csrf", "cross-site request forgery"],
            "rce": ["remote code execution", "rce", "command injection"],
            "lfi": ["local file inclusion", "lfi", "path traversal"],
            "xxe": ["xxe", "xml external entity"],
            "ssrf": ["ssrf", "server-side request forgery"],
            "idor": ["idor", "insecure direct object reference"],
            "auth_bypass": ["authentication bypass", "auth bypass"],
            "broken_access": ["broken access control", "authorization"],
        }
        
        for vuln_type, keywords in classifications.items():
            if any(kw in title_lower or kw in desc_lower for kw in keywords):
                return vuln_type
        
        return "unknown"
    
    async def _search_cves(self, vuln_type: str, finding: Finding) -> List[Dict[str, Any]]:
        """Search for related CVEs using Exa and AI knowledge"""
        cves = []
        
        # 1. Try Exa Search first
        if self.exa_client.api_key:
            query = f"CVE for {finding.title} {finding.target} vulnerability"
            try:
                self.logger.info(f"Searching Exa for: {query}")
                results = await self.exa_client.search(
                    query, 
                    num_results=5, 
                    use_autoprompt=True
                )
                
                # Extract CVEs from search results
                for res in results:
                    # Use highlights if available for better context
                    text = ""
                    if res.get("highlights"):
                        text = " ... ".join(res["highlights"])
                    else:
                        text = res.get("text", "") or res.get("title", "")
                        
                    found_ids = re.findall(self.cve_patterns, text)
                    for cve_id in found_ids:
                        if cve_id not in [c['cve_id'] for c in cves]:
                            cves.append({
                                "cve_id": cve_id,
                                "description": res.get("title", "Related search result"),
                                "summary": text[:200] + "..." if len(text) > 200 else text,
                                "url": res.get("url", ""),
                                "source": "Exa Search"
                            })
            except Exception as e:
                self.logger.warning(f"Exa search failed, falling back to AI: {e}")

        # 2. Fallback to AI generation if few results
        if len(cves) < 2:
            prompt = f"""Search for CVEs related to this vulnerability:

**Vulnerability Type:** {vuln_type}
**Title:** {finding.title}
**Description:** {finding.description}
**Target:** {finding.target}

Provide:
1. List of relevant CVE IDs (CVE-YYYY-NNNNN format)
2. For each CVE:
   - CVE ID
   - Description
   - CVSS Score
   - Affected software/versions
   - Exploitation difficulty

Format as a structured list.
"""
            
            result = await self.think(
                prompt,
                "You are a security researcher with access to CVE databases. Provide accurate CVE information."
            )
            
            # Parse CVE IDs from response
            cve_ids = re.findall(self.cve_patterns, result["response"])
            
            for cve_id in set(cve_ids):  # Remove duplicates
                if cve_id not in [c['cve_id'] for c in cves]:
                    cve_info = await self._get_cve_details(cve_id, result["response"])
                    cves.append(cve_info)
        
        return cves
    
    async def _get_cve_details(self, cve_id: str, context: str) -> Dict[str, Any]:
        """Extract CVE details from AI response"""
        
        # Try to extract details from context
        cve_section = ""
        for line in context.split('\n'):
            if cve_id in line:
                # Get surrounding context
                idx = context.find(line)
                cve_section = context[max(0, idx-200):idx+500]
                break
        
        # Use AI to structure the information
        prompt = f"""Extract structured information about {cve_id} from this text:

{cve_section}

Provide:
- Description (brief)
- CVSS Score (if mentioned)
- Severity
- Affected software
- Exploitation difficulty

Format as JSON-like structure.
"""
        
        result = await self.gemini.generate(prompt)
        
        return {
            "cve_id": cve_id,
            "description": self._extract_field(result, "description") or f"Related to {cve_id}",
            "cvss_score": self._extract_field(result, "cvss") or "N/A",
            "severity": self._extract_field(result, "severity") or "Unknown",
            "affected_software": self._extract_field(result, "affected") or "See CVE details",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source": "AI Knowledge"
        }
    
    async def _identify_cwes(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Identify relevant CWE categories"""
        
        # Common CWE mappings
        cwe_mappings = {
            "xss": [
                {"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation"},
                {"id": "CWE-80", "name": "Improper Neutralization of Script-Related HTML Tags"},
            ],
            "sqli": [
                {"id": "CWE-89", "name": "SQL Injection"},
                {"id": "CWE-564", "name": "SQL Injection: Hibernate"},
            ],
            "csrf": [
                {"id": "CWE-352", "name": "Cross-Site Request Forgery"},
            ],
            "rce": [
                {"id": "CWE-78", "name": "OS Command Injection"},
                {"id": "CWE-94", "name": "Improper Control of Generation of Code"},
            ],
            "lfi": [
                {"id": "CWE-22", "name": "Path Traversal"},
                {"id": "CWE-98", "name": "PHP File Inclusion"},
            ],
            "xxe": [
                {"id": "CWE-611", "name": "XML External Entity Reference"},
            ],
            "ssrf": [
                {"id": "CWE-918", "name": "Server-Side Request Forgery"},
            ],
        }
        
        cwes = cwe_mappings.get(vuln_type, [])
        
        # Enrich with AI analysis
        if cwes:
            for cwe in cwes:
                cwe["url"] = f"https://cwe.mitre.org/data/definitions/{cwe['id'].split('-')[1]}.html"
        
        return cwes
    
    async def _search_exploits(self, vuln_type: str, finding: Finding) -> List[Dict[str, Any]]:
        """Search for known exploits using Exa and AI"""
        exploits = []
        
        # 1. Try Exa Search first
        if self.exa_client.api_key:
            query = f"Exploit PoC for {finding.title} {vuln_type} github"
            try:
                self.logger.info(f"Searching Exa for exploits: {query}")
                results = await self.exa_client.search(
                    query, 
                    num_results=5, 
                    use_autoprompt=True
                )
                
                for res in results:
                    exploits.append({
                        "source": "Exa Search",
                        "id": "External Link",
                        "url": res.get("url", ""),
                        "type": "Public Exploit (Unverified)",
                        "description": res.get("title", "")
                    })
            except Exception as e:
                self.logger.warning(f"Exa exploit search failed: {e}")

        # 2. Fallback/Augment with AI knowledge
        prompt = f"""Search for known public exploits related to this vulnerability:

**Type:** {vuln_type}
**Finding:** {finding.title}
**Description:** {finding.description}

Provide:
1. Exploit database references (ExploitDB, Metasploit, etc.)
2. Proof-of-concept repositories
3. Security tool modules
4. Known attack frameworks

For each exploit:
- Name/Title
- Source (ExploitDB, GitHub, Metasploit, etc.)
- Reliability
- Requirements
- Brief description

Limit to top 5 most relevant exploits.
"""
        
        result = await self.think(
            prompt,
            "You are a penetration tester researching public exploits. Provide accurate information."
        )
        
        # Parse exploits from response (regex helper)
        # Look for ExploitDB IDs
        edb_ids = re.findall(r'EDB-ID[:\s]+(\d+)', result["response"], re.IGNORECASE)
        for edb_id in edb_ids[:5]:
            exploits.append({
                "source": "ExploitDB",
                "id": f"EDB-{edb_id}",
                "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                "type": "Public Exploit",
            })
        
        # Look for Metasploit modules
        msf_modules = re.findall(r'exploit/([a-z_/]+)', result["response"])
        for module in msf_modules[:3]:
            exploits.append({
                "source": "Metasploit",
                "module": f"exploit/{module}",
                "type": "Metasploit Module",
            })
        
        # If no specific exploits found and none from Exa, create generic entry
        if not exploits:
            exploits.append({
                "source": "Generic",
                "description": f"Search exploit databases for '{vuln_type}' exploits",
                "type": "Research Required",
            })
        
        return exploits
    
    async def _analyze_attack_patterns(self, vuln_type: str, finding: Finding) -> List[Dict[str, Any]]:
        """Analyze common attack patterns"""
        
        prompt = f"""Analyze attack patterns for this vulnerability:

**Type:** {vuln_type}
**Finding:** {finding.title}

Provide:
1. Common attack vectors
2. Typical exploitation techniques
3. Attack chain possibilities
4. Lateral movement opportunities
5. Persistence mechanisms

For each pattern:
- Attack vector name
- Technique description
- Prerequisites
- Detection methods
- Countermeasures

Focus on practical, real-world attack scenarios.
"""
        
        result = await self.think(
            prompt,
            "You are a red team operator analyzing attack patterns. Be thorough and practical."
        )
        
        # Structure the response
        patterns = []
        
        # Parse numbered patterns
        pattern_matches = re.findall(r'\d+\.\s+([^\n]+)', result["response"])
        for idx, pattern in enumerate(pattern_matches[:5], 1):
            patterns.append({
                "id": idx,
                "name": pattern.strip(),
                "description": f"Attack pattern for {vuln_type}",
                "severity": finding.severity,
            })
        
        return patterns
    
    async def _research_mitigations(self, vuln_type: str, finding: Finding) -> List[Dict[str, Any]]:
        """Research mitigation strategies"""
        
        prompt = f"""Research comprehensive mitigation strategies for:

**Vulnerability Type:** {vuln_type}
**Specific Finding:** {finding.title}
**Context:** {finding.description}

Provide:
1. Immediate mitigations (quick fixes)
2. Short-term solutions (within days)
3. Long-term solutions (architectural changes)
4. Defense-in-depth measures
5. Monitoring and detection strategies

For each mitigation:
- Category (Immediate/Short-term/Long-term)
- Action required
- Effectiveness rating
- Implementation complexity
- Side effects or considerations

Prioritize by effectiveness and ease of implementation.
"""
        
        result = await self.think(
            prompt,
            "You are a security architect providing mitigation strategies. Be comprehensive and practical."
        )
        
        mitigations = []
        
        # Parse mitigations by category
        categories = ["immediate", "short-term", "long-term"]
        for category in categories:
            # Find section for this category
            pattern = rf'{category}[:\s]+(.+?)(?={"|".join(categories)}|$)'
            match = re.search(pattern, result["response"], re.IGNORECASE | re.DOTALL)
            
            if match:
                section = match.group(1)
                # Extract bullet points or numbered items
                items = re.findall(r'[-•\d]+\.\s*([^\n]+)', section)
                
                for item in items[:3]:  # Limit to 3 per category
                    mitigations.append({
                        "category": category.title(),
                        "action": item.strip(),
                        "priority": "High" if category == "immediate" else "Medium",
                    })
        
        return mitigations
    
    async def _perform_risk_analysis(self, finding: Finding, research: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive risk analysis"""
        
        prompt = f"""Perform a comprehensive risk analysis:

**Vulnerability:** {finding.title}
**Severity:** {finding.severity}
**Target:** {finding.target}

**Research Context:**
- Related CVEs: {len(research['cves'])}
- Known Exploits: {len(research['known_exploits'])}
- CWE Categories: {[c['id'] for c in research['cwes']]}

Analyze:
1. **Likelihood of Exploitation** (Low/Medium/High)
   - Exploit availability
   - Skill level required
   - Attack complexity

2. **Business Impact** (Low/Medium/High/Critical)
   - Data confidentiality impact
   - Data integrity impact
   - Availability impact
   - Reputation damage
   - Compliance violations

3. **Overall Risk Rating** (Low/Medium/High/Critical)
   - Combined likelihood and impact
   - Justification

4. **Recommended Priority** (P0/P1/P2/P3)
   - P0: Fix immediately
   - P1: Fix within 24 hours
   - P2: Fix within 1 week
   - P3: Fix within 1 month

Provide structured analysis with clear ratings and justifications.
"""
        
        result = await self.think(
            prompt,
            "You are a risk analyst providing business-focused security risk assessment."
        )
        
        response = result["response"]
        
        return {
            "likelihood": self._extract_rating(response, "likelihood"),
            "impact": self._extract_rating(response, "impact"),
            "overall_risk": self._extract_rating(response, "overall risk"),
            "priority": self._extract_priority(response),
            "justification": response,
            "cvss_base": self._calculate_cvss_base(finding, research),
        }
    
    def _gather_references(self, vuln_type: str) -> List[Dict[str, str]]:
        """Gather reference materials"""
        
        references = {
            "xss": [
                {"title": "OWASP XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
                {"title": "PortSwigger XSS Guide", "url": "https://portswigger.net/web-security/cross-site-scripting"},
            ],
            "sqli": [
                {"title": "OWASP SQL Injection Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
                {"title": "SQLMap Documentation", "url": "https://github.com/sqlmapproject/sqlmap/wiki"},
            ],
            "csrf": [
                {"title": "OWASP CSRF Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
            ],
            "rce": [
                {"title": "OWASP Command Injection", "url": "https://owasp.org/www-community/attacks/Command_Injection"},
            ],
        }
        
        return references.get(vuln_type, [
            {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"},
        ])
    
    def _extract_field(self, text: str, field_name: str) -> Optional[str]:
        """Extract field from text"""
        pattern = rf'{field_name}[:\s]+([^\n]+)'
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def _extract_rating(self, text: str, rating_type: str) -> str:
        """Extract rating from text"""
        pattern = rf'{rating_type}[:\s]+(Low|Medium|High|Critical)'
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).title() if match else "Unknown"
    
    def _extract_priority(self, text: str) -> str:
        """Extract priority from text"""
        pattern = r'P[0-3]'
        match = re.search(pattern, text)
        return match.group(0) if match else "P2"
    
    def _calculate_cvss_base(self, finding: Finding, research: Dict[str, Any]) -> float:
        """Calculate CVSS base score"""
        severity_scores = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0,
        }
        
        base_score = severity_scores.get(finding.severity.lower(), 5.0)
        
        # Adjust based on research
        if len(research.get("cves", [])) > 0:
            base_score += 0.5
        if len(research.get("known_exploits", [])) > 0:
            base_score += 1.0
        
        return min(10.0, base_score)
