"""
Gemini AI Integration Module for Sentinel AI System
Handles all Gemini AI interactions for threat analysis
"""

import json
import logging
import os
import re
import sys
import time
from typing import Dict, Any, Optional, List

# Make google.genai import optional to prevent server crash
try:
    import google.genai as genai
    from google.genai.types import GenerateContentConfig, HttpOptions
    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    GenerateContentConfig = None
    HttpOptions = None
    GENAI_AVAILABLE = False

# Legacy fallback: google-generativeai - REMOVED to eliminate deprecation warnings
# The system now uses google.genai exclusively
LEGACY_GENAI_AVAILABLE = False
legacy_genai = None

try:
    from app.config import settings
except ImportError:
    # Fallback when running from within the server package context.
    from server.app.config import settings

logger = logging.getLogger(__name__)

# Skip expensive API tests during startup to preserve quota
SKIP_STARTUP_TESTS = os.getenv("SKIP_GEMINI_STARTUP_TESTS", "true").lower() == "true"

class GeminiIntegration:
    """Gemini AI integration for advanced threat analysis"""
    
    def __init__(self):
        self.client = None
        self.available_models = []
        self.initialized = False
        self.backend = None
        self.api_keys: List[str] = []
        self.active_key_index: int = 0
        self._last_error: str = ""
        self._last_model_used: str = ""
        self._last_key_used_index: int = 0
        self._quota_cooldown_until: float = 0.0
        self.model_candidates = [
            item.strip()
            for item in os.getenv("GEMINI_MODEL_CANDIDATES", "gemini-2.5-flash,gemini-2.5-pro,gemini-2.0-flash").split(",")
            if item.strip()
        ]
        if not self.model_candidates:
            self.model_candidates = ["gemini-2.5-flash"]
        try:
            self.max_attempts = int(os.getenv("GEMINI_MAX_ATTEMPTS", "3"))
        except Exception:
            self.max_attempts = 3
        self.max_attempts = max(1, min(self.max_attempts, 5))
        try:
            self.min_request_interval = float(os.getenv("GEMINI_MIN_REQUEST_INTERVAL", "1.5"))
        except Exception:
            self.min_request_interval = 1.5
        self.min_request_interval = max(0.2, self.min_request_interval)
        self._last_request_ts = 0.0
        try:
            self.request_timeout_seconds = float(os.getenv("GEMINI_REQUEST_TIMEOUT_SECONDS", "45"))
        except Exception:
            self.request_timeout_seconds = 45.0
        self.request_timeout_seconds = max(10.0, min(self.request_timeout_seconds, 120.0))
        try:
            self.quota_cooldown_seconds = int(os.getenv("GEMINI_QUOTA_COOLDOWN_SECONDS", "180"))
        except Exception:
            self.quota_cooldown_seconds = 180
        self.quota_cooldown_seconds = max(30, self.quota_cooldown_seconds)
        self._initialize()

    def _collect_api_keys(self) -> List[str]:
        """Collect Gemini API keys from settings and env, deduplicated."""
        csv_keys: List[str] = []
        for csv_env in ("GEMINI_API_KEYS", "GOOGLE_API_KEYS"):
            raw = os.getenv(csv_env, "")
            if raw:
                csv_keys.extend([part.strip() for part in raw.split(",") if part.strip()])

        key_candidates = [
            getattr(settings, "GEMINI_API_KEY", "") if settings else "",
            os.getenv("GEMINI_API_KEY", ""),
            os.getenv("GOOGLE_API_KEY", ""),
            *csv_keys,
        ]
        for idx in range(1, 21):
            key_candidates.append(os.getenv(f"GEMINI_API_KEY_{idx}", ""))
            key_candidates.append(os.getenv(f"GOOGLE_API_KEY_{idx}", ""))

        deduped: List[str] = []
        seen = set()
        for candidate in key_candidates:
            value = str(candidate or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

    def _get_api_key(self) -> str:
        """Get preferred API key from pooled keys."""
        return self.api_keys[0] if self.api_keys else ""

    def _build_client(self, api_key: str):
        if not GENAI_AVAILABLE:
            return None
        return genai.Client(
            api_key=api_key,
            http_options=HttpOptions(api_version='v1alpha')
        )

    def _classify_error(self, message: str) -> str:
        lower = str(message or "").lower()
        if "429" in lower or "resource_exhausted" in lower or "quota" in lower or "rate limit" in lower:
            return "quota"
        if "401" in lower or "403" in lower or "invalid api key" in lower or "permission" in lower or "unauthorized" in lower:
            return "auth"
        if "model" in lower and ("not found" in lower or "unsupported" in lower):
            return "model"
        if "timeout" in lower or "temporarily" in lower or "unavailable" in lower:
            return "transient"
        return "other"

    def _extract_retry_delay_seconds(self, message: str) -> int:
        text = str(message or "")
        patterns = [
            r"retryDelay'?:\s*'?(\d+)s'?,?",
            r"retry in\s+([0-9]+(?:\.[0-9]+)?)s",
            r"retry after\s+([0-9]+(?:\.[0-9]+)?)s",
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                try:
                    return max(1, int(float(m.group(1))))
                except Exception:
                    continue
        return 0
    
    def _initialize(self):
        """Initialize Gemini AI client"""
        if not GENAI_AVAILABLE and not LEGACY_GENAI_AVAILABLE:
            logger.warning("google.genai not installed. AI features will be limited.")
            logger.warning(f"Gemini import check failed under: {sys.executable} (VIRTUAL_ENV={os.getenv('VIRTUAL_ENV')})")
            return
            
        self.api_keys = self._collect_api_keys()
        if not self.api_keys:
            logger.warning("Gemini API key not configured. AI features will be limited.")
            return

        usable_keys = [k for k in self.api_keys if len(k) >= 20]
        if not usable_keys:
            logger.warning("⚠️ All configured Gemini API keys appear invalid (too short).")
            return
        self.api_keys = usable_keys
        
        try:
            if GENAI_AVAILABLE:
                self.backend = "google-genai"
                for idx, api_key in enumerate(self.api_keys):
                    try:
                        candidate_client = self._build_client(api_key)
                        models = candidate_client.models.list()
                        candidate_models = [model.name for model in models if 'gemini' in model.name.lower()]
                        self.client = candidate_client
                        self.available_models = candidate_models
                        self.active_key_index = idx
                        self.initialized = True
                        logger.info(
                            "✅ Gemini AI initialized with key #%d (%d total keys). Models: %s",
                            idx + 1,
                            len(self.api_keys),
                            self.available_models[:3] if self.available_models else self.model_candidates[:3],
                        )
                        break
                    except Exception as e:
                        self._last_error = str(e)
                        continue
                if not self.initialized:
                    logger.error("❌ Failed to initialize Gemini with configured keys: %s", self._last_error or "unknown error")
                    return
            elif LEGACY_GENAI_AVAILABLE:
                # Legacy google-generativeai client
                legacy_genai.configure(api_key=self.api_keys[0])
                self.client = legacy_genai
                self.backend = "google-generativeai"

                # Try to list models if available
                try:
                    models = self.client.list_models()
                    self.available_models = [m.name for m in models if 'gemini' in m.name.lower()]
                    if not self.available_models:
                        logger.warning("⚠️ Gemini API key may be expired or invalid - no models available")
                        self.initialized = False
                        return
                    logger.info(f"✅ Gemini AI initialized (legacy). Available models: {self.available_models[:3]}")
                    logger.info(f"✅ API key is valid and active")
                except Exception as e:
                    error_msg = str(e)
                    if "expired" in error_msg.lower() or "invalid" in error_msg.lower() or "401" in error_msg or "403" in error_msg:
                        logger.error(f"❌ Gemini API key expired or invalid: {error_msg}")
                        self.initialized = False
                        return
                    logger.warning(f"Legacy Gemini client initialized; model list unavailable: {e}")
                self.initialized = True
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize Gemini AI: {e}")
            self.initialized = False
    
    def is_available(self) -> bool:
        """Check if Gemini AI is available"""
        return self.initialized and self.client is not None
    
    def check_availability(self) -> Dict[str, Any]:
        """
        Check Gemini availability and return status.

        This should be safe and fast for health checks. Avoid real-time
        API calls here to prevent endpoint timeouts if external Gemini
        connect is slow or unavailable.
        """
        if not self.is_available():
            return {
                'available': False,
                'status': 'not_available',
                'message': 'Gemini AI not initialized or unavailable'
            }

        if SKIP_STARTUP_TESTS:
            # Skip expensive runtime checks in integration mode.
            return {
                'available': True,
                'status': 'ready',
                'message': 'Gemini AI initialized (startup tests skipped)',
                'model': self.available_models[0] if self.available_models else 'gemini-2.5-flash',
                'models_available': len(self.available_models),
                'keys_available': len(self.api_keys),
                'active_key_index': self.active_key_index + 1,
            }

        # If tests are enabled, do a lightweight non-blocking check where possible.
        try:
            model_name = self.available_models[0] if self.available_models else 'gemini-2.5-flash'
            return {
                'available': True,
                'status': 'ready',
                'message': 'Gemini AI initialized',
                'model': model_name,
                'models_available': len(self.available_models),
                'keys_available': len(self.api_keys),
                'active_key_index': self.active_key_index + 1,
            }
        except Exception as e:
            logger.warning(f"Gemini availability check minor failure: {e}")
            return {
                'available': False,
                'status': 'error',
                'message': f'Gemini availability check failed: {e}',
                'model': 'N/A',
                'models_available': len(self.available_models),
                'keys_available': len(self.api_keys),
                'active_key_index': self.active_key_index + 1,
            }

    def generate_text(self, prompt: str, max_output_tokens: int = 4000, temperature: float = 0.1) -> Dict[str, Any]:
        """Generate text with key/model failover across configured API keys."""
        if not self.is_available():
            return {"success": False, "error": "Gemini AI not available", "text": None}

        now = time.time()
        if now < float(self._quota_cooldown_until or 0.0):
            remaining = int(max(1, self._quota_cooldown_until - now))
            return {"success": False, "error": f"quota cooldown active ({remaining}s)", "text": None}

        elapsed = now - float(self._last_request_ts or 0.0)
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self._last_request_ts = time.time()

        if self.backend == "google-generativeai":
            try:
                model_name = self.model_candidates[0]
                model = self.client.GenerativeModel(model_name)
                response = model.generate_content(
                    prompt,
                    generation_config={
                        "temperature": temperature,
                        "max_output_tokens": max_output_tokens,
                        "top_p": 0.8,
                        "top_k": 40,
                    },
                )
                text = getattr(response, "text", None)
                return {"success": bool(text), "text": text, "model": model_name, "key_index": 1, "error": ""}
            except Exception as e:
                return {"success": False, "error": str(e), "text": None}

        last_error = ""
        key_pool = self.api_keys[:] if self.api_keys else []
        if key_pool and 0 <= self.active_key_index < len(key_pool):
            key_pool = key_pool[self.active_key_index:] + key_pool[:self.active_key_index]

        for attempt in range(1, self.max_attempts + 1):
            for key_offset, api_key in enumerate(key_pool):
                client = None
                try:
                    client = self._build_client(api_key)
                except Exception as e:
                    last_error = str(e)
                    continue

                for model_name in self.model_candidates:
                    try:
                        response = client.models.generate_content(
                            model=model_name,
                            contents=prompt,
                            config=GenerateContentConfig(
                                temperature=temperature,
                                max_output_tokens=max_output_tokens,
                                top_p=0.8,
                                top_k=40,
                            )
                        )
                        text = getattr(response, "text", None)
                        if text:
                            self.client = client
                            self._last_model_used = model_name
                            self._last_key_used_index = key_offset + 1
                            self.active_key_index = (self.active_key_index + key_offset) % max(1, len(self.api_keys))
                            self._last_error = ""
                            return {
                                "success": True,
                                "text": text,
                                "model": model_name,
                                "key_index": self.active_key_index + 1,
                                "error": "",
                            }
                    except Exception as e:
                        message = str(e)
                        last_error = message
                        kind = self._classify_error(message)
                        if kind == "quota":
                            retry_delay = self._extract_retry_delay_seconds(message)
                            effective_cooldown = max(
                                int(self.quota_cooldown_seconds),
                                int(retry_delay) if retry_delay else 0,
                            )
                            self._quota_cooldown_until = max(
                                float(self._quota_cooldown_until or 0.0),
                                time.time() + float(effective_cooldown),
                            )
                            continue
                        if kind == "auth":
                            break
                        if kind == "model":
                            continue
                        continue
            if attempt < self.max_attempts:
                time.sleep(min(1.0 * attempt, 3.0))

        self._last_error = last_error or "Gemini generation failed"
        return {"success": False, "error": self._last_error, "text": None}
    
    async def analyze_with_gemini(self, prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze content with Gemini AI (async wrapper)
        
        Args:
            prompt: The prompt to send to Gemini
            context: Optional context dictionary
            
        Returns:
            Dict with analysis results
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'Gemini AI not available',
                'fallback': True
            }
        
        try:
            generation = self.generate_text(prompt)
            response = generation.get("text") if generation.get("success") else None
            if response:
                return {
                    'success': True,
                    'response': response,
                    'model': generation.get("model") or (self.available_models[0] if self.available_models else 'gemini-2.5-flash'),
                    'key_index': generation.get("key_index", 1),
                }
            else:
                return {
                    'success': False,
                    'error': generation.get("error") or 'No response from Gemini',
                    'fallback': True
                }
        except Exception as e:
            logger.error(f"Gemini analysis error: {e}")
            return {
                'success': False,
                'error': str(e),
                'fallback': True
            }
    
    def analyze_threat(self, scan_data: Dict[str, Any], scan_type: str = "general") -> Optional[Dict[str, Any]]:
        """
        Analyze threat using Gemini AI
        
        Args:
            scan_data: Dictionary containing scan results from various services
            scan_type: Type of scan (file, url, ip, system)
            
        Returns:
            Dictionary with threat analysis or None if failed
        """
        if not self.is_available():
            logger.warning("Gemini AI not available for analysis")
            return None
        
        try:
            # Format data for Gemini
            formatted_data = self._format_for_analysis(scan_data, scan_type)
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(formatted_data, scan_type)
            
            # Generate content
            response = self._generate_content(prompt)
            if not response:
                return None
            
            # Parse response
            analysis = self._parse_analysis_response(response, scan_type)
            
            logger.info(f"✅ Gemini analysis completed for {scan_type} scan")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Gemini analysis failed: {e}", exc_info=True)
            return None
    
    def _format_for_analysis(self, scan_data: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Format scan data for Gemini analysis"""
        formatted = {
            "metadata": {
                "scan_type": scan_type,
                "analysis_timestamp": "current",
                "data_sources": list(scan_data.keys())
            },
            "scan_results": {}
        }
        
        for service, data in scan_data.items():
            if not data:
                formatted["scan_results"][service] = {"status": "no_data"}
                continue
            
            try:
                if service == "virustotal":
                    formatted["scan_results"][service] = self._format_virustotal_data(data)
                elif service == "abuseipdb":
                    formatted["scan_results"][service] = self._format_abuseipdb_data(data)
                elif service == "shodan":
                    formatted["scan_results"][service] = self._format_shodan_data(data)
                elif service == "urlscan":
                    formatted["scan_results"][service] = self._format_urlscan_data(data)
                elif service == "hybrid_analysis":
                    formatted["scan_results"][service] = self._format_hybrid_analysis_data(data)
                else:
                    formatted["scan_results"][service] = {
                        "status": "data_present",
                        "summary": f"Raw data available ({len(str(data))} chars)"
                    }
            except Exception as e:
                logger.warning(f"Error formatting {service} data: {e}")
                formatted["scan_results"][service] = {"status": "format_error", "error": str(e)}
        
        return formatted
    
    def _format_virustotal_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal data"""
        if "found" in data and not data["found"]:
            return {"status": "not_found", "in_database": False}
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "status": "analyzed",
                "in_database": True,
                "detection_stats": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "total_engines": sum(stats.values())
                },
                "reputation": attributes.get("reputation", 0),
                "popular_threat_names": self._extract_threat_names(attributes.get("last_analysis_results", {}))
            }
        except Exception as e:
            return {"status": "parse_error", "error": str(e)}
    
    def _format_abuseipdb_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format AbuseIPDB data"""
        try:
            ip_data = data.get("data", {})
            
            return {
                "status": "analyzed",
                "abuse_confidence": ip_data.get("abuseConfidenceScore", 0),
                "total_reports": ip_data.get("totalReports", 0),
                "country": ip_data.get("countryCode", "Unknown"),
                "isp": ip_data.get("isp", "Unknown"),
                "domain": ip_data.get("domain", "Unknown"),
                "last_reported": ip_data.get("lastReportedAt", "Unknown")
            }
        except Exception as e:
            return {"status": "parse_error", "error": str(e)}
    
    def _format_shodan_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format Shodan data"""
        try:
            return {
                "status": "analyzed",
                "open_ports": data.get("ports", []),
                "vulnerability_count": len(data.get("vulns", {})),
                "organization": data.get("org", "Unknown"),
                "country": data.get("country_name", "Unknown"),
                "operating_system": data.get("os", "Unknown"),
                "services": len(data.get("data", []))
            }
        except Exception as e:
            return {"status": "parse_error", "error": str(e)}
    
    def _format_urlscan_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format URLScan data"""
        try:
            verdicts = data.get("verdicts", {})
            overall = verdicts.get("overall", {})
            
            return {
                "status": "analyzed",
                "malicious": overall.get("malicious", False),
                "score": overall.get("score", 0),
                "categories": overall.get("categories", []),
                "brands": data.get("brands", []),
                "tags": data.get("tags", [])
            }
        except Exception as e:
            return {"status": "parse_error", "error": str(e)}
    
    def _format_hybrid_analysis_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format Hybrid Analysis data"""
        try:
            if isinstance(data, list) and len(data) > 0:
                item = data[0]
                return {
                    "status": "analyzed",
                    "verdict": item.get("verdict", "Unknown"),
                    "threat_score": item.get("threat_score", 0),
                    "malware_family": item.get("vx_family", "Unknown"),
                    "tags": item.get("tags", [])
                }
            else:
                return {"status": "no_results"}
        except Exception as e:
            return {"status": "parse_error", "error": str(e)}
    
    def _extract_threat_names(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract threat names from VirusTotal results"""
        threat_names = []
        for engine, result in analysis_results.items():
            if result.get("category") == "malicious":
                threat_name = result.get("result", "")
                if threat_name and threat_name not in ["None", "null", ""]:
                    threat_names.append(threat_name)
        return list(set(threat_names))[:5]  # Return top 5 unique names
    
    def _create_analysis_prompt(self, formatted_data: Dict[str, Any], scan_type: str) -> str:
        """Create prompt for Gemini analysis"""
        data_json = json.dumps(formatted_data, indent=2)
        
        prompt = f"""You are a senior cybersecurity threat intelligence analyst. 
Analyze the following {scan_type} scan data and provide a comprehensive threat assessment.

SCAN DATA:
{data_json}

Provide your analysis in this EXACT JSON format:
{{
    "risk_assessment": {{
        "risk_score": <float 0.0-1.0>,
        "risk_level": "<CLEAN|LOW|MEDIUM|HIGH|CRITICAL>",
        "confidence": <float 0.0-1.0>
    }},
    "threat_analysis": {{
        "primary_threats": ["<threat1>", "<threat2>", ...],
        "threat_indicators": ["<indicator1>", "<indicator2>", ...],
        "attack_vectors": ["<vector1>", "<vector2>", ...],
        "potential_impact": "<low|medium|high|critical>"
    }},
    "detailed_findings": {{
        "summary": "<brief_summary>",
        "analysis_by_service": {{
            "<service_name>": "<service_specific_analysis>"
        }},
        "key_observations": ["<observation1>", "<observation2>", ...]
    }},
    "recommendations": {{
        "immediate_actions": ["<action1>", "<action2>", ...],
        "remediation_steps": ["<step1>", "<step2>", ...],
        "preventive_measures": ["<measure1>", "<measure2>", ...]
    }},
    "context": {{
        "analysis_methodology": "<how_analysis_was_done>",
        "limitations": "<any_limitations>",
        "additional_notes": "<any_additional_notes>"
    }}
}}

CRITICAL GUIDELINES:
1. Risk Score: 0.0-0.2=CLEAN, 0.2-0.4=LOW, 0.4-0.6=MEDIUM, 0.6-0.8=HIGH, 0.8-1.0=CRITICAL
2. Threat types: malware, phishing, network_attack, data_exfiltration, ransomware, 
   command_control, credential_theft, denial_of_service, privilege_escalation
3. Be specific and evidence-based - reference actual data points
4. If data is limited, acknowledge it and adjust confidence
5. Provide actionable, prioritized recommendations
6. Consider real-world impact and business context
7. Format ALL text in plain English, no markdown
8. Return ONLY the JSON object, no additional text
"""

        return prompt
    
    def _generate_content(self, prompt: str) -> Optional[str]:
        """Generate content using Gemini with quota handling"""
        if not self.is_available():
            return None
        result = self.generate_text(prompt)
        if result.get("success"):
            logger.info(
                "Gemini content generation succeeded | model=%s | key#%s",
                result.get("model", "unknown"),
                result.get("key_index", "?"),
            )
            return result.get("text")
        logger.warning("Gemini content generation failed: %s", result.get("error", "unknown error"))
        return None
    
    def _parse_analysis_response(self, response_text: str, scan_type: str) -> Dict[str, Any]:
        """Parse Gemini response into structured analysis"""
        try:
            # Clean the response
            text = response_text.strip()
            
            # Try to find complete JSON by matching braces
            start = text.find('{')
            if start == -1:
                logger.error("No JSON found in Gemini response")
                return self._create_fallback_analysis(scan_type)
            
            # Find matching closing brace
            brace_count = 0
            end = -1
            for i in range(start, len(text)):
                if text[i] == '{':
                    brace_count += 1
                elif text[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break
            
            if end == -1:
                logger.error("No matching closing brace found in Gemini response")
                return self._create_fallback_analysis(scan_type)
            
            json_str = text[start:end]
            
            # Try parsing with lenient mode
            try:
                analysis = json.loads(json_str)
            except json.JSONDecodeError:
                # Try to fix common JSON issues
                json_str = json_str.replace('\n', ' ').replace('\r', '')
                # Remove trailing commas
                json_str = json_str.replace(',}', '}').replace(',]', ']')
                analysis = json.loads(json_str)
            
            # Validate required structure
            if self._validate_analysis_structure(analysis):
                # Add metadata
                analysis["metadata"] = {
                    "analyzed_by": "gemini_ai",
                    "scan_type": scan_type,
                    "model_used": "gemini-2.5-flash",
                    "timestamp": "current"
                }
                return analysis
            else:
                logger.warning("Gemini response missing required fields")
                return self._create_fallback_analysis(scan_type)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON: {e}")
            logger.debug(f"Response text: {response_text[:500]}")
            return self._create_fallback_analysis(scan_type)
        except Exception as e:
            logger.error(f"Error parsing Gemini response: {e}")
            return self._create_fallback_analysis(scan_type)
    
    def _validate_analysis_structure(self, analysis: Dict[str, Any]) -> bool:
        """Validate that analysis has required structure"""
        required_sections = ["risk_assessment", "threat_analysis", "recommendations"]
        
        for section in required_sections:
            if section not in analysis:
                return False
        
        # Check risk assessment fields
        risk_assessment = analysis.get("risk_assessment", {})
        if not all(key in risk_assessment for key in ["risk_score", "risk_level", "confidence"]):
            return False
        
        # Validate risk score range
        risk_score = risk_assessment.get("risk_score", 0)
        if not isinstance(risk_score, (int, float)) or not 0 <= risk_score <= 1:
            return False
        
        return True
    
    def _create_fallback_analysis(self, scan_type: str) -> Dict[str, Any]:
        """Create fallback analysis when Gemini fails"""
        logger.warning("Creating fallback analysis")
        
        return {
            "metadata": {
                "analyzed_by": "fallback_analysis",
                "scan_type": scan_type,
                "note": "Gemini AI analysis failed, using fallback"
            },
            "risk_assessment": {
                "risk_score": 0.5,
                "risk_level": "MEDIUM",
                "confidence": 0.3
            },
            "threat_analysis": {
                "primary_threats": ["unknown"],
                "threat_indicators": ["ai_analysis_unavailable"],
                "attack_vectors": ["unknown"],
                "potential_impact": "unknown"
            },
            "detailed_findings": {
                "summary": "AI analysis unavailable. Manual review recommended.",
                "analysis_by_service": {},
                "key_observations": ["Gemini AI service unavailable"]
            },
            "recommendations": {
                "immediate_actions": ["Review scan results manually"],
                "remediation_steps": ["Consider alternative analysis methods"],
                "preventive_measures": ["Ensure AI service connectivity"]
            },
            "context": {
                "analysis_methodology": "fallback_rules",
                "limitations": "AI analysis service unavailable",
                "additional_notes": "This is an automated fallback response"
            }
        }
    
    def generate_threat_report(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive threat report from analysis"""
        try:
            risk_assessment = analysis.get("risk_assessment", {})
            threat_analysis = analysis.get("threat_analysis", {})
            recommendations = analysis.get("recommendations", {})
            
            report = {
                "report_header": {
                    "title": "AI-Powered Threat Intelligence Report",
                    "generated_by": "Sentinel AI with Gemini AI",
                    "timestamp": "current",
                    "report_id": f"threat_report_{hash(str(analysis))}"
                },
                "executive_summary": {
                    "overall_risk": risk_assessment.get("risk_level", "UNKNOWN"),
                    "risk_score": risk_assessment.get("risk_score", 0.0),
                    "confidence": risk_assessment.get("confidence", 0.0),
                    "primary_threats": threat_analysis.get("primary_threats", []),
                    "summary": analysis.get("detailed_findings", {}).get("summary", "No summary available")
                },
                "detailed_analysis": threat_analysis,
                "action_plan": {
                    "priority": "HIGH" if risk_assessment.get("risk_score", 0) > 0.7 else 
                               "MEDIUM" if risk_assessment.get("risk_score", 0) > 0.4 else "LOW",
                    "timeline": self._get_action_timeline(risk_assessment.get("risk_score", 0)),
                    "recommendations": recommendations
                },
                "technical_details": {
                    "analysis_method": analysis.get("context", {}).get("analysis_methodology", "unknown"),
                    "confidence_factors": self._get_confidence_factors(risk_assessment.get("confidence", 0)),
                    "limitations": analysis.get("context", {}).get("limitations", "None specified")
                },
                "appendix": {
                    "risk_scale": "0.0-0.2: CLEAN, 0.2-0.4: LOW, 0.4-0.6: MEDIUM, 0.6-0.8: HIGH, 0.8-1.0: CRITICAL",
                    "confidence_scale": "0.0-0.3: Low, 0.3-0.6: Medium, 0.6-0.8: High, 0.8-1.0: Very High",
                    "report_version": "2.0"
                }
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating threat report: {e}")
            return {"error": "Failed to generate report", "details": str(e)}
    
    def _get_action_timeline(self, risk_score: float) -> str:
        """Get action timeline based on risk score"""
        if risk_score >= 0.8:
            return "Immediate (within 1 hour)"
        elif risk_score >= 0.6:
            return "Urgent (within 4 hours)"
        elif risk_score >= 0.4:
            return "Soon (within 24 hours)"
        else:
            return "When convenient"
    
    def _get_confidence_factors(self, confidence: float) -> List[str]:
        """Get confidence factors based on confidence score"""
        if confidence >= 0.8:
            return ["High data quality", "Multiple sources", "Clear indicators"]
        elif confidence >= 0.6:
            return ["Moderate data", "Some sources", "Probable indicators"]
        elif confidence >= 0.4:
            return ["Limited data", "Few sources", "Possible indicators"]
        else:
            return ["Very limited data", "Uncertain indicators"]
    
    def test_connection(self) -> Dict[str, Any]:
        """Test Gemini AI connection (skips actual API call to preserve quota)"""
        if not self.is_available():
            return {
                "status": "error",
                "message": "Gemini AI not initialized. Check API key.",
                "available": False
            }
        
        # Skip expensive API tests to preserve daily quota
        if SKIP_STARTUP_TESTS:
            logger.debug("Skipping Gemini API test call to preserve quota")
            return {
                "status": "success",
                "message": "Gemini AI ready (test skipped to preserve quota)",
                "response": "Connection test skipped",
                "model_used": self.available_models[0] if self.available_models else "gemini-2.5-flash",
                "available_models": self.available_models[:5],
                "initialized": True,
                "test_skipped": True,
                "keys_available": len(self.api_keys),
                "active_key_index": self.active_key_index + 1,
            }
        
        try:
            # Use the first available model or fall back to a known working model
            test_model = self.available_models[0] if self.available_models else "gemini-2.5-flash"
            
            # Simple test prompt
            result = self.generate_text(
                "Hello, respond with 'Gemini AI is working' if functional.",
                max_output_tokens=20,
                temperature=0.0,
            )
            response_text = result.get("text") if result.get("success") else "Connection test failed"
            
            return {
                "status": "success" if result.get("success") else "error",
                "message": "Gemini AI connection successful" if result.get("success") else result.get("error", "Gemini test failed"),
                "response": response_text,
                "model_used": result.get("model", test_model),
                "available_models": self.available_models[:5],
                "initialized": bool(result.get("success")),
                "keys_available": len(self.api_keys),
                "active_key_index": result.get("key_index", self.active_key_index + 1),
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Gemini AI test failed: {str(e)}",
                "available": False,
                "initialized": False
            }

# Singleton instance
gemini_integration = GeminiIntegration()

def get_gemini_client() -> GeminiIntegration:
    """
    Get the singleton Gemini integration instance
    
    Returns:
        GeminiIntegration: Singleton instance of Gemini integration
    """
    # Re-initialize if API key became available after module import
    if not gemini_integration.is_available() and gemini_integration._get_api_key():
        gemini_integration._initialize()
    return gemini_integration

def get_analysis_status() -> Dict[str, Any]:
    """
    Get current Gemini analysis status
    
    Returns:
        Dict with current status information
    """
    client = get_gemini_client()
    
    if not client.is_available():
        return {
            'available': False,
            'status': 'not_available',
            'model': 'N/A',
            'message': 'Gemini AI is not initialized or unavailable'
        }
    
    availability = client.check_availability()
    return {
        'available': availability.get('available', False),
        'status': 'ready' if availability.get('available', False) else 'not_available',
        'model': availability.get('model', 'N/A'),
        'message': availability.get('message', 'Unknown status')
    }
