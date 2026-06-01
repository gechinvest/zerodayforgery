import unittest
import asyncio
from unittest.mock import AsyncMock, patch
from src.core.engine import AdvancedScanner, Vulnerability, Severity, VulnType


class TestAdvancedScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = AdvancedScanner()

    def test_initialization(self):
        self.assertIsNotNone(self.scanner)
        self.assertEqual(len(self.scanner.vulnerabilities), 0)

    def test_vulnerability_creation(self):
        vuln = Vulnerability(
            id="test123",
            type=VulnType.XSS,
            severity=Severity.HIGH,
            url="https://example.com",
            description="Test XSS",
            remediation="Fix it",
            cwe_id="CWE-79",
            cvss_score=6.1
        )
        self.assertEqual(vuln.id, "test123")
        self.assertEqual(vuln.type, VulnType.XSS)
        self.assertEqual(vuln.severity, Severity.HIGH)


if __name__ == '__main__':
    unittest.main()
