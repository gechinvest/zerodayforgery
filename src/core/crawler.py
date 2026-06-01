import logging
import re
from typing import List, Set, Dict, Any
from urllib.parse import urlparse, urljoin
import asyncio
from bs4 import BeautifulSoup

from .engine import AdvancedScanner


class AdvancedCrawler:
    def __init__(self, scanner: AdvancedScanner):
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_params: Set[str] = set()

    async def crawl(self, start_url: str, max_depth: int = 3, max_pages: int = 100):
        self.logger.info(f"Starting crawl on {start_url}, max depth: {max_depth}, max pages: {max_pages}")
        await self._crawl_recursive(start_url, 0, max_depth, max_pages)
        return {
            'endpoints': list(self.discovered_endpoints),
            'parameters': list(self.discovered_params)
        }

    async def _crawl_recursive(self, url: str, depth: int, max_depth: int, max_pages: int):
        if depth > max_depth or len(self.visited_urls) >= max_pages or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.discovered_endpoints.add(url)
        
        try:
            response = await self.scanner.request(url)
            if response.get('status') != 200:
                return
            
            content = response.get('content', '')
            soup = BeautifulSoup(content, 'html.parser')
            
            links = self._extract_urls(content, url)
            js_files = self._extract_js_urls(content, url)
            params = self._extract_parameters(content)
            
            self.discovered_params.update(params)
            
            for js_file in js_files:
                await self._analyze_javascript(js_file)
            
            for link in links:
                await self._crawl_recursive(link, depth + 1, max_depth, max_pages)
                await asyncio.sleep(self.scanner.config.get('delay', 0.1))
                
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")

    def _extract_urls(self, html: str, base_url: str) -> List[str]:
        urls = set()
        soup = BeautifulSoup(html, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.scheme in ['http', 'https'] and parsed.netloc == urlparse(base_url).netloc:
                urls.add(full_url.split('#')[0].split('?')[0])
        return list(urls)

    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        urls = set()
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            parsed = urlparse(full_url)
            if parsed.scheme in ['http', 'https']:
                urls.add(full_url)
        return list(urls)

    def _extract_parameters(self, html: str) -> Set[str]:
        params = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    params.add(name)
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if '?' in href:
                query = href.split('?')[1]
                for param in query.split('&'):
                    if '=' in param:
                        params.add(param.split('=')[0])
        
        return params

    def _extract_api_endpoints(self, js_content: str) -> List[str]:
        endpoints = set()
        patterns = [
            r'["\'](/api/[a-zA-Z0-9/_-]+)["\']',
            r'["\'](/[a-zA-Z0-9/_-]+/api/[a-zA-Z0-9/_-]+)["\']',
            r'url:\s*["\']([a-zA-Z0-9/_-]+)["\']',
            r'endpoint:\s*["\']([a-zA-Z0-9/_-]+)["\']',
            r'path:\s*["\']([a-zA-Z0-9/_-]+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            endpoints.update(matches)
        
        return list(endpoints)

    async def _analyze_javascript(self, js_url: str):
        try:
            response = await self.scanner.request(js_url)
            content = response.get('content', '')
            api_endpoints = self._extract_api_endpoints(content)
            for endpoint in api_endpoints:
                parsed = urlparse(js_url)
                full_endpoint = f"{parsed.scheme}://{parsed.netloc}{endpoint}"
                self.discovered_endpoints.add(full_endpoint)
        except Exception as e:
            self.logger.error(f"Error analyzing JS {js_url}: {str(e)}")

    def _generate_parameter_wordlist(self) -> List[str]:
        return [
            'id', 'user', 'profile', 'account', 'order', 'product', 'item',
            'page', 'limit', 'offset', 'search', 'q', 'query', 'filter',
            'category', 'type', 'lang', 'locale', 'redirect', 'url', 'next',
            'callback', 'jsonp', 'callback', 'from', 'to', 'date', 'time',
            'sort', 'orderby', 'dir', 'asc', 'desc', 'view', 'mode', 'theme',
            'color', 'size', 'width', 'height', 'x', 'y', 'coord', 'lat', 'lng',
            'email', 'username', 'password', 'pass', 'pwd', 'token', 'session',
            'api_key', 'secret', 'key', 'auth', 'access', 'refresh', 'code'
        ]

    async def _test_custom_endpoints(self):
        pass
