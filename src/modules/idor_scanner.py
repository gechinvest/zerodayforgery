import re
import logging
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import asyncio

from ..core.engine import AdvancedScanner, Vulnerability, Severity, VulnType


class IDORModule:
    def __init__(self, scanner: AdvancedScanner):
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self.id_patterns = [
            r'\/(\d{1,10})(?:\/|$|\?)',
            r'[\?&](id|user|profile|account|order|product)=([a-fA-F0-9]{32})',
            r'[\?&](id|user|profile|account|order|product)=([a-fA-F0-9-]{36})',
            r'[\?&](id|user|profile|account|order|product)=(\d{1,10})',
            r'[\?&](id|user|profile|account|order|product)=([A-Za-z0-9+/]+=*)'
        ]
        self.sensitive_data_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-.\s]?){3}\d{4}\b',
            'api_key': r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
            'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-!@#$%^&*]{4,})["\']?',
            'balance': r'(?i)(balance|amount|credit|debit)["\']?\s*[:=]\s*["\']?([\$€£]?\d+(?:\.\d{2})?)["\']?'
        }
        self.test_ids = [1, 2, 3, 4, 5, 10, 100, 999, 1000]
        self.discovered_endpoints: Set[str] = set()

    async def scan(self, target_url: str):
        self.logger.info(f"Starting IDOR scan on {target_url}")
        await self._discover_endpoints(target_url)
        await self._test_idor_endpoints()
        await self._test_privilege_escalation(target_url)

    async def _discover_endpoints(self, base_url: str):
        try:
            response = await self.scanner.request(base_url)
            content = response.get('content', '')
            
            for pattern in self.id_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    endpoint = base_url
                    if match.group(0).startswith(('?', '&')):
                        param_name = match.group(1)
                        endpoint = base_url
                    else:
                        endpoint = base_url
                    self.discovered_endpoints.add(endpoint)
        except Exception as e:
            self.logger.error(f"Error discovering endpoints: {str(e)}")

    async def _test_idor_endpoints(self):
        for endpoint in self.discovered_endpoints:
            ids_from_url = self._extract_ids_from_url(endpoint)
            for original_id in ids_from_url:
                for test_id in self.test_ids:
                    if str(original_id) != str(test_id):
                        test_url = self._replace_id_in_url(endpoint, original_id, test_id)
                        await self._test_endpoint(test_url, endpoint, test_id)
                        await asyncio.sleep(self.scanner.config.get('delay', 0.1))

    def _extract_ids_from_url(self, url: str) -> List[str]:
        ids = []
        parsed = urlparse(url)
        
        path_parts = parsed.path.split('/')
        for part in path_parts:
            if part.isdigit() and len(part) <= 10:
                ids.append(part)
        
        params = parse_qs(parsed.query)
        for param, values in params.items():
            if param.lower() in ['id', 'user', 'profile', 'account', 'order', 'product']:
                ids.extend(values)
        
        return ids

    def _replace_id_in_url(self, url: str, original_id: str, new_id: any) -> str:
        parsed = urlparse(url)
        
        new_path = parsed.path
        if str(original_id) in new_path.split('/'):
            path_parts = new_path.split('/')
            new_path_parts = [str(new_id) if part == str(original_id) else part for part in path_parts]
            new_path = '/'.join(new_path_parts)
        
        new_query = parsed.query
        params = parse_qs(new_query)
        for param, values in params.items():
            if str(original_id) in values:
                params[param] = [str(new_id) if v == str(original_id) else v for v in values]
        new_query = urlencode(params, doseq=True)
        
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            new_path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    async def _test_endpoint(self, test_url: str, original_endpoint: str, test_id: any):
        try:
            response = await self.scanner.request(test_url)
            status = response.get('status')
            content = response.get('content', '')
            
            if status == 200:
                sensitive_findings = await self._analyze_sensitive_data(content)
                if sensitive_findings:
                    vuln = Vulnerability(
                        id=self.scanner.generate_vuln_id(),
                        type=VulnType.IDOR,
                        severity=Severity.HIGH,
                        url=test_url,
                        parameter=None,
                        payload=str(test_id),
                        evidence=', '.join(sensitive_findings),
                        description="IDOR vulnerability detected - unauthorized access to sensitive data",
                        remediation="Implement proper access control checks. Verify user permissions for every request.",
                        cwe_id="CWE-639",
                        cvss_score=7.5
                    )
                    self.scanner.add_vulnerability(vuln)
        except Exception as e:
            self.logger.error(f"Error testing endpoint {test_url}: {str(e)}")

    async def _analyze_sensitive_data(self, content: str) -> List[str]:
        findings = []
        for data_type, pattern in self.sensitive_data_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append(f"{data_type}: {len(matches)} occurrences")
        return findings

    async def _test_privilege_escalation(self, base_url: str):
        admin_endpoints = [
            '/admin',
            '/admin/users',
            '/admin/dashboard',
            '/api/admin',
            '/api/admin/users'
        ]
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for admin_path in admin_endpoints:
            admin_url = base + admin_path
            response = await self.scanner.request(admin_url)
            if response.get('status') == 200:
                vuln = Vulnerability(
                    id=self.scanner.generate_vuln_id(),
                    type=VulnType.IDOR,
                    severity=Severity.CRITICAL,
                    url=admin_url,
                    parameter=None,
                    payload=None,
                    evidence=f"Status 200 on admin endpoint",
                    description="Unauthorized access to admin endpoint detected",
                    remediation="Restrict admin endpoints to authenticated and authorized users only.",
                    cwe_id="CWE-285",
                    cvss_score=9.8
                )
                self.scanner.add_vulnerability(vuln)
            await asyncio.sleep(self.scanner.config.get('delay', 0.1))
