import logging
import aiohttp
from typing import Optional, Dict, Any


class AIDetector:
    def __init__(self, model_name: str = "tinydolphin", ollama_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.ollama_url = ollama_url
        self.logger = logging.getLogger(__name__)

    async def check_ollama_available(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.ollama_url}/api/tags", timeout=5) as resp:
                    return resp.status == 200
        except Exception as e:
            self.logger.warning(f"Ollama not available: {str(e)}")
            return False

    async def download_model(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_url}/api/pull",
                    json={"name": self.model_name},
                    timeout=300
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            self.logger.error(f"Failed to download model: {str(e)}")
            return False

    async def verify_xss(self, url: str, parameter: Optional[str], payload: str, response_preview: str) -> str:
        available = await self.check_ollama_available()
        if not available:
            return "NEEDS_MANUAL"
        
        prompt = f"""Analyze this potential XSS vulnerability and respond with only one word: CONFIRMED, FALSE_POSITIVE, or NEEDS_MANUAL.
URL: {url}
Parameter: {parameter}
Payload: {payload}
Response preview: {response_preview[:500]}"""
        
        result = await self._call_ollama(prompt)
        if "CONFIRMED" in result:
            return "CONFIRMED"
        elif "FALSE_POSITIVE" in result or "false" in result.lower():
            return "FALSE_POSITIVE"
        else:
            return "NEEDS_MANUAL"

    async def verify_idor(self, url: str, response_data: str, user_context: Optional[str] = None) -> str:
        available = await self.check_ollama_available()
        if not available:
            return "NEEDS_MANUAL"
        
        prompt = f"""Analyze this potential IDOR vulnerability and respond with only one word: CONFIRMED, FALSE_POSITIVE, or NEEDS_MANUAL.
URL: {url}
Response data preview: {response_data[:500]}"""
        
        result = await self._call_ollama(prompt)
        if "CONFIRMED" in result:
            return "CONFIRMED"
        elif "FALSE_POSITIVE" in result or "false" in result.lower():
            return "FALSE_POSITIVE"
        else:
            return "NEEDS_MANUAL"

    async def verify_sqli(self, url: str, parameter: Optional[str], payload: str, response_preview: str) -> str:
        available = await self.check_ollama_available()
        if not available:
            return "NEEDS_MANUAL"
        
        prompt = f"""Analyze this potential SQL injection vulnerability and respond with only one word: CONFIRMED, FALSE_POSITIVE, or NEEDS_MANUAL.
URL: {url}
Parameter: {parameter}
Payload: {payload}
Response preview: {response_preview[:500]}"""
        
        result = await self._call_ollama(prompt)
        if "CONFIRMED" in result:
            return "CONFIRMED"
        elif "FALSE_POSITIVE" in result or "false" in result.lower():
            return "FALSE_POSITIVE"
        else:
            return "NEEDS_MANUAL"

    async def _call_ollama(self, prompt: str) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_url}/api/generate",
                    json={"model": self.model_name, "prompt": prompt, "stream": False},
                    timeout=60
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "")
                    return ""
        except Exception as e:
            self.logger.error(f"Ollama call failed: {str(e)}")
            return ""

    async def generate_payload_suggestions(self, vuln_type: str, context: str) -> list:
        available = await self.check_ollama_available()
        if not available:
            return []
        
        prompt = f"""Generate 5 new {vuln_type} payloads based on this context: {context}
Respond only with a JSON array of payloads, no other text."""
        
        try:
            result = await self._call_ollama(prompt)
            import json
            return json.loads(result)
        except Exception as e:
            self.logger.error(f"Failed to generate payload suggestions: {str(e)}")
            return []

    async def analyze_response_behavior(self, request: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
        return {"analysis": "AI analysis not available", "status": "SKIPPED"}
