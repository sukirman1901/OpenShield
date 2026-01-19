"""
Test script for Research Agent with Exa MCP
Demonstrates the agent's ability to "reason" and find real-world data.
"""

import asyncio
import os
from dotenv import load_dotenv
from core.research_agent import ResearchAgent
from core.memory import PentestMemory, Finding
from ai.factory import create_client
from utils.helpers import load_config

# Load env for API keys
load_dotenv()

async def test_research_logic():
    print("\n" + "="*80)
    print("🧠 Testing Research Agent (Exa MCP Integration)")
    print("="*80)

    # Check for API Key
    if not os.getenv("EXA_API_KEY"):
        print("⚠️  Warning: EXA_API_KEY not found in environment.")
        print("   The agent will fallback to AI knowledge (simulated research).")
        print("   To test real search, export EXA_API_KEY='your-key'\n")

    config = load_config("openshield.yaml")
    memory = PentestMemory("test_target")
    ai_client = create_client(config)
    
    agent = ResearchAgent(config, ai_client, memory)

    # Simulate a finding that needs "reasoning"
    # Apache 2.4.49 is famously vulnerable to Path Traversal (CVE-2021-41773)
    finding = Finding(
        id="test_apache_vuln",
        severity="high",
        title="Apache 2.4.49 Detected",
        description="The web server is running Apache 2.4.49. This version might be vulnerable to known issues.",
        evidence="Server: Apache/2.4.49",
        tool="nmap",
        target="http://example.com",
        timestamp="2026-01-10T00:00:00"
    )

    print(f"🔍 Analyzing Finding: {finding.title}")
    print(f"📝 Description: {finding.description}")
    print("-" * 40)

    try:
        results = await agent.research_vulnerability(finding)
        
        print("\n✅ Research Complete!")
        print("\n1️⃣  Vulnerability Classification:")
        print(f"   Type: {results['vulnerability_type']}")
        
        print("\n2️⃣  CVE Findings (Nalar / Knowledge):")
        if results['cves']:
            for cve in results['cves'][:3]:
                print(f"   - {cve['cve_id']}: {cve['description'][:100]}...")
                print(f"     Source: {cve.get('source', 'Unknown')}")
        else:
            print("   No CVEs found.")

        print("\n3️⃣  Exploit Search (Resources):")
        if results['known_exploits']:
            for exp in results['known_exploits'][:3]:
                print(f"   - {exp['type']}: {exp.get('description', '')[:50]}...")
                print(f"     Link: {exp.get('url', 'N/A')}")
        else:
            print("   No public exploits found.")

        print("\n4️⃣  Risk Analysis (Reasoning):")
        risk = results['risk_analysis']
        print(f"   Likelihood: {risk.get('likelihood')}")
        print(f"   Impact: {risk.get('impact')}")
        print(f"   Overall Risk: {risk.get('overall_risk')}")
        print(f"   Justification: {risk.get('justification')[:150]}...")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_research_logic())
