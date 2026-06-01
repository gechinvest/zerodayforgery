#!/usr/bin/env python3
import argparse
import asyncio
import logging
import sys
from datetime import datetime
from colorama import init, Fore, Style

from src.core.engine import AdvancedScanner, Severity
from src.core.reporter import ReportGenerator

init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("logs/scanner.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def print_banner():
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════════════╗
║                    ZERO-DAY FORGE SCANNER                     ║
║           Advanced Vulnerability Detection & Analysis         ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


async def run_scan(args):
    config = {
        'max_threads': args.threads,
        'timeout': args.timeout,
        'delay': args.delay,
        'proxy': args.proxy,
        'verify_ssl': False
    }
    
    scanner = AdvancedScanner(config)
    scan_info = {
        'target_url': args.url,
        'started_at': datetime.utcnow().isoformat(),
        'scanner_version': '1.0.0'
    }
    
    try:
        print(f"\n{Fore.YELLOW}[*] Starting scan on {args.url}")
        print(f"[*] Threads: {args.threads}, Delay: {args.delay}s\n")
        
        await scanner.scan(args.url)
        
        scan_info['completed_at'] = datetime.utcnow().isoformat()
        
        print(f"\n{Fore.GREEN}[+] Scan completed!")
        print(f"\n{Style.BRIGHT}=== Vulnerability Summary ==={Style.RESET_ALL}")
        
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in scanner.vulnerabilities:
            summary[vuln.severity.value.lower()] += 1
        
        print(f"{Fore.RED}  Critical: {summary['critical']}")
        print(f"{Fore.MAGENTA}  High: {summary['high']}")
        print(f"{Fore.YELLOW}  Medium: {summary['medium']}")
        print(f"{Fore.CYAN}  Low: {summary['low']}")
        print(f"{Fore.WHITE}  Info: {summary['info']}")
        print(f"\n  Total: {len(scanner.vulnerabilities)} vulnerabilities found")
        
        if len(scanner.vulnerabilities) > 0:
            print(f"\n{Fore.GREEN}[*] Generating reports...")
            reporter = ReportGenerator(scanner.vulnerabilities, scan_info)
            reports = reporter.generate_all()
            
            print(f"\n{Style.BRIGHT}=== Generated Reports ==={Style.RESET_ALL}")
            for fmt, path in reports.items():
                print(f"  {fmt.upper()}: {path}")
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n{Fore.RED}[!] Scan failed: {str(e)}")
        logger.exception("Scan failed")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Zero-Day Forge - Professional Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Maximum concurrent threads (default: 20)')
    parser.add_argument('-o', '--output', choices=['json', 'html', 'csv', 'markdown', 'all'], default='all',
                        help='Output format (default: all)')
    parser.add_argument('--xss', action='store_true', help='Only scan for XSS vulnerabilities')
    parser.add_argument('--idor', action='store_true', help='Only scan for IDOR vulnerabilities')
    parser.add_argument('--sqli', action='store_true', help='Only scan for SQL injection vulnerabilities')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://localhost:8080)')
    parser.add_argument('--ai', action='store_true', help='Enable AI verification (requires Ollama)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print_banner()
    
    return asyncio.run(run_scan(args))


if __name__ == '__main__':
    sys.exit(main())
