import random
import time
import logging
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class RateLimiter:
    def __init__(self, max_requests_per_second: float = 100):
        self.max_requests_per_second = max_requests_per_second
        self.requests = []

    def wait_if_needed(self):
        now = time.time()
        self.requests = [t for t in self.requests if now - t < 1.0]
        if len(self.requests) >= self.max_requests_per_second:
            time.sleep(1.0 - (now - self.requests[0]))
        self.requests.append(now)


class NetworkManager:
    def __init__(self, max_threads: int = 20, timeout: int = 10, proxy: Optional[str] = None):
        self.max_threads = max_threads
        self.timeout = timeout
        self.proxy = proxy
        self.logger = logging.getLogger(__name__)
        self.user_agents = self._get_user_agents()
        self.rate_limiter = RateLimiter()

    def _get_user_agents(self) -> List[str]:
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
        ]

    def get_random_user_agent(self) -> str:
        return random.choice(self.user_agents)

    def get_random_headers(self) -> Dict[str, str]:
        return {
            'User-Agent': self.get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }

    def check_rate_limiting(self, response: Dict[str, Any]) -> bool:
        status = response.get('status', 0)
        if status in [429, 503]:
            return True
        headers = response.get('headers', {})
        if 'retry-after' in headers:
            return True
        return False

    def calculate_response_time(self, start_time: float) -> float:
        return time.time() - start_time

    def extract_links(self, html: str, base_url: str) -> List[str]:
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.scheme in ['http', 'https']:
                    links.add(full_url)
        except Exception as e:
            self.logger.error(f"Error extracting links: {str(e)}")
        return list(links)

    def extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                for inp in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': inp.get('name'),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    }
                    form_data['inputs'].append(input_info)
                forms.append(form_data)
        except Exception as e:
            self.logger.error(f"Error extracting forms: {str(e)}")
        return forms
