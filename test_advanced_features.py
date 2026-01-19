"""
Test script for advanced exploitation features
"""

import asyncio
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.helpers import load_config
from core.smart_shield import OpenShieldSmartAgent
from core.exploit_generator_agent import ExploitGeneratorAgent
from core.remediation_agent import RemediationAgent
from core.exploitation_workflow import ExploitationWorkflow
from core.memory import PentestMemory, Finding
from ai.factory import create_client


async def test_browser_agent():
    """Test browser agent"""
    print("\n" + "="*80)
    print("🧪 Testing Browser Agent")
    print("="*80)
    
    config = load_config("openshield.yaml")
    memory = PentestMemory("test_target")
    ai_client = create_client(config)
    
    from core.browser_agent import BrowserAgent
    browser_agent = BrowserAgent(config, ai_client, memory)
    
    # Test with a safe target
    test_url = "http://testphp.vulnweb.com"
    print(f"\n🌐 Analyzing: {test_url}")
    
    try:
        results = await browser_agent.analyze_web(test_url, max_depth=1)
        print(f"\n✅ Analysis complete!")
        print(f"   Findings: {len(results['findings'])}")
        print(f"   Screenshot: {results['screenshot']}")
        
        for finding in results['findings']:
            print(f"\n   [{finding.severity.upper()}] {finding.title}")
            print(f"   Evidence: {finding.evidence[:100]}...")
        
        return results
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None


async def test_exploit_generator():
    """Test exploit generator"""
    print("\n" + "="*80)
    print("🧪 Testing Exploit Generator")
    print("="*80)
    
    config = load_config("openshield.yaml")
    memory = PentestMemory("test_target")
    ai_client = create_client(config)
    
    exploit_gen = ExploitGeneratorAgent(config, ai_client, memory)
    
    # Create a test finding
    test_finding = Finding(
        id="test_xss_1",
        severity="high",
        title="Reflected XSS in search parameter",
        description="User input is reflected without sanitization",
        evidence="Parameter: q, URL: http://example.com/search",
        tool="test",
        target="http://example.com/search",
        timestamp="2026-01-10T00:00:00"
    )
    
    print(f"\n⚡ Generating exploit for: {test_finding.title}")
    
    try:
        exploit = await exploit_gen.generate_poc(test_finding)
        print(f"\n✅ Exploit generated!")
        print(f"   Type: {exploit.get('type')}")
        print(f"   Payload: {exploit.get('payload')}")
        print(f"\n   Python PoC:")
        print("   " + "\n   ".join(exploit.get('python_code', '').split('\n')[:10]))
        
        return exploit
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None


async def test_remediation_agent():
    """Test remediation agent"""
    print("\n" + "="*80)
    print("🧪 Testing Remediation Agent")
    print("="*80)
    
    config = load_config("openshield.yaml")
    memory = PentestMemory("test_target")
    ai_client = create_client(config)
    
    remediation = RemediationAgent(config, ai_client, memory)
    
    # Create a test finding
    test_finding = Finding(
        id="test_xss_1",
        severity="high",
        title="XSS vulnerability",
        description="User input is not sanitized",
        evidence="",
        tool="test",
        target="http://example.com",
        timestamp="2026-01-10T00:00:00"
    )
    
    vulnerable_code = "echo $_GET['search'];"
    
    print(f"\n🛠️  Generating fix for: {test_finding.title}")
    print(f"   Vulnerable code: {vulnerable_code}")
    
    try:
        fix = await remediation.generate_fix(test_finding, vulnerable_code, "php")
        print(f"\n✅ Remediation generated!")
        print(f"\n   Fixed code:")
        print(f"   {fix.get('fixed')}")
        print(f"\n   Explanation:")
        print(f"   {fix.get('explanation')}")
        
        return fix
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return None


async def test_full_workflow():
    """Test complete exploitation workflow"""
    print("\n" + "="*80)
    print("🧪 Testing Full Exploitation Workflow")
    print("="*80)
    
    config = load_config("openshield.yaml")
    
    # Use a safe test target
    test_url = "http://testphp.vulnweb.com"
    
    print(f"\n🚀 Running full exploitation on: {test_url}")
    print("   This may take a few minutes...")
    
    try:
        workflow = ExploitationWorkflow(config, test_url)
        results = await workflow.run_full_exploitation()
        
        print(f"\n✅ Workflow complete!")
        print(f"\n📊 Results:")
        print(f"   Findings: {len(results['findings'])}")
        print(f"   Exploits: {len(results['exploits'])}")
        print(f"   Remediations: {len(results['remediations'])}")
        
        if results['findings']:
            print(f"\n📋 Sample findings:")
            for finding in results['findings'][:3]:
                print(f"   - [{finding.severity.upper()}] {finding.title}")
        
        return results
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None


async def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("🔐 OpenShield Advanced Features - Test Suite")
    print("="*80)
    
    # Test individual components
    print("\n📝 Running component tests...")
    
    # Test 1: Exploit Generator (no browser required)
    await test_exploit_generator()
    
    # Test 2: Remediation Agent (no browser required)
    await test_remediation_agent()
    
    # Test 3: Browser Agent (requires Playwright)
    print("\n⚠️  Browser tests require Playwright installation")
    print("   Run: playwright install chromium")
    
    try:
        await test_browser_agent()
    except Exception as e:
        print(f"\n⚠️  Browser test skipped: {e}")
    
    # Test 4: Full workflow (optional, takes longer)
    run_full = input("\n\nRun full exploitation workflow test? (y/n): ")
    if run_full.lower() == 'y':
        await test_full_workflow()
    
    print("\n" + "="*80)
    print("✅ Test suite completed!")
    print("="*80)


if __name__ == "__main__":
    asyncio.run(main())
