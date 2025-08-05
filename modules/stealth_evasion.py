#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo Stealth Evasion
Recursos avançados de stealth e anti-detecção para testes de penetração
"""

import time
import random
import logging
import requests
import socket
from typing import Dict, List, Any, Optional, Tuple
import threading
import queue
from urllib.parse import urlparse
import base64
import hashlib

class StealthEvasion:
    """
    Módulo para evasão de detecção e técnicas stealth avançadas
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
        # User agents realistas para rotação
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0',
        ]
        
        # Padrões de timing humano
        self.human_timing_patterns = {
            'browsing': [0.5, 1.2, 0.8, 2.1, 0.9, 1.5, 0.7, 3.2],
            'searching': [1.0, 2.5, 1.8, 0.9, 2.1, 1.3, 0.6, 1.9],
            'reading': [3.0, 5.2, 4.1, 2.8, 6.5, 3.7, 4.9, 2.3],
            'typing': [0.1, 0.3, 0.2, 0.15, 0.25, 0.18, 0.12, 0.22]
        }
        
        # Proxy pools para rotação
        self.proxy_pools = []
        
        # Session pools para distribuição
        self.session_pool = []
        self._initialize_session_pool()
        
    def _initialize_session_pool(self):
        """Inicializa pool de sessões HTTP"""
        for i in range(5):
            session = requests.Session()
            session.verify = False
            session.timeout = 30
            self.session_pool.append(session)
    
    def stealth_scan_mode(self, target: str, scan_type: str = 'normal') -> Dict[str, Any]:
        """
        Executa scan em modo stealth avançado
        """
        self.logger.info(f"👻 Iniciando scan stealth em {target}")
        
        stealth_config = {
            'target': target,
            'scan_type': scan_type,
            'stealth_level': 'maximum',
            'anti_detection': True,
            'techniques': []
        }
        
        # Aplicar técnicas stealth baseadas no tipo
        if scan_type == 'ghost':
            stealth_config.update(self._ghost_mode_config())
        elif scan_type == 'ninja':
            stealth_config.update(self._ninja_mode_config())
        elif scan_type == 'phantom':
            stealth_config.update(self._phantom_mode_config())
        else:
            stealth_config.update(self._normal_stealth_config())
        
        return stealth_config
    
    def _ghost_mode_config(self) -> Dict[str, Any]:
        """
        Configuração modo fantasma - máxima evasão
        """
        return {
            'request_delay': (10, 30),
            'randomize_timing': True,
            'rotate_user_agents': True,
            'rotate_proxies': True,
            'fragment_requests': True,
            'randomize_headers': True,
            'session_rotation': True,
            'traffic_mimicry': 'human_browsing',
            'decoy_requests': True,
            'request_jitter': 0.8,
            'techniques': ['slow_scan', 'traffic_mimicry', 'decoy_traffic', 'session_rotation']
        }
    
    def _ninja_mode_config(self) -> Dict[str, Any]:
        """
        Configuração modo ninja - stealth balanceado
        """
        return {
            'request_delay': (5, 15),
            'randomize_timing': True,
            'rotate_user_agents': True,
            'fragment_requests': False,
            'randomize_headers': True,
            'session_rotation': False,
            'traffic_mimicry': 'human_searching',
            'decoy_requests': False,
            'request_jitter': 0.5,
            'techniques': ['timing_variation', 'header_rotation', 'user_agent_rotation']
        }
    
    def _phantom_mode_config(self) -> Dict[str, Any]:
        """
        Configuração modo phantom - invisibilidade total
        """
        return {
            'request_delay': (15, 45),
            'randomize_timing': True,
            'rotate_user_agents': True,
            'rotate_proxies': True,
            'fragment_requests': True,
            'randomize_headers': True,
            'session_rotation': True,
            'traffic_mimicry': 'human_reading',
            'decoy_requests': True,
            'request_jitter': 0.9,
            'anonymization': 'maximum',
            'techniques': ['ultra_slow', 'massive_decoy', 'proxy_chains', 'tor_routing']
        }
    
    def _normal_stealth_config(self) -> Dict[str, Any]:
        """
        Configuração stealth normal
        """
        return {
            'request_delay': (2, 8),
            'randomize_timing': True,
            'rotate_user_agents': True,
            'randomize_headers': False,
            'traffic_mimicry': 'automated_tool',
            'request_jitter': 0.3,
            'techniques': ['basic_timing', 'user_agent_rotation']
        }
    
    def intelligent_rate_limiting(self, target: str, base_delay: float = 1.0) -> float:
        """
        Rate limiting inteligente baseado em resposta do servidor
        """
        # Analisar comportamento do servidor
        server_behavior = self._analyze_server_behavior(target)
        
        # Ajustar delay baseado na análise
        if server_behavior.get('rate_limiting_detected'):
            adjusted_delay = base_delay * random.uniform(3.0, 8.0)
            self.logger.warning(f"⚠️ Rate limiting detectado, aumentando delay para {adjusted_delay:.2f}s")
        elif server_behavior.get('ids_signatures_detected'):
            adjusted_delay = base_delay * random.uniform(5.0, 12.0)
            self.logger.warning(f"🚨 Possível IDS detectado, delay crítico: {adjusted_delay:.2f}s")
        else:
            adjusted_delay = base_delay * random.uniform(0.5, 2.0)
        
        return adjusted_delay
    
    def _analyze_server_behavior(self, target: str) -> Dict[str, bool]:
        """
        Analisa comportamento do servidor para detectar mecanismos de defesa
        """
        behavior = {
            'rate_limiting_detected': False,
            'ids_signatures_detected': False,
            'waf_detected': False,
            'honeypot_indicators': False
        }
        
        try:
            # Teste de rate limiting
            session = random.choice(self.session_pool)
            responses = []
            
            for i in range(3):
                start_time = time.time()
                response = session.get(f'http://{target}', timeout=10)
                end_time = time.time()
                
                responses.append({
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'headers': dict(response.headers)
                })
                
                time.sleep(0.1)  # Requests rápidos para testar rate limiting
            
            # Analisar padrões
            status_codes = [r['status_code'] for r in responses]
            response_times = [r['response_time'] for r in responses]
            
            # Detectar rate limiting
            if any(code in [429, 503, 509] for code in status_codes):
                behavior['rate_limiting_detected'] = True
            
            # Detectar variações suspeitas no tempo de resposta
            if max(response_times) - min(response_times) > 5.0:
                behavior['ids_signatures_detected'] = True
            
            # Detectar WAF pelos headers
            waf_headers = ['cf-ray', 'x-sucuri-id', 'x-akamai', 'server: cloudflare']
            for response in responses:
                for header, value in response['headers'].items():
                    if any(waf_sig in f"{header}: {value}".lower() for waf_sig in waf_headers):
                        behavior['waf_detected'] = True
                        break
                        
        except Exception as e:
            self.logger.debug(f"Erro na análise de comportamento: {e}")
        
        return behavior
    
    def human_behavior_simulation(self, requests_queue: queue.Queue, target: str):
        """
        Simula comportamento humano realista
        """
        self.logger.info(f"🤖 Iniciando simulação de comportamento humano para {target}")
        
        while not requests_queue.empty():
            try:
                request_info = requests_queue.get_nowait()
                
                # Simular padrões humanos de navegação
                self._simulate_human_browsing_pattern(target, request_info)
                
                # Delays realistas entre ações
                delay_pattern = random.choice(list(self.human_timing_patterns.values()))
                delay = random.choice(delay_pattern)
                
                self.logger.debug(f"💤 Delay humano: {delay:.2f}s")
                time.sleep(delay)
                
                requests_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                self.logger.debug(f"Erro na simulação humana: {e}")
    
    def _simulate_human_browsing_pattern(self, target: str, request_info: Dict):
        """
        Simula padrão de navegação humana
        """
        session = random.choice(self.session_pool)
        
        # Rotacionar User-Agent
        session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })
        
        # Adicionar headers humanos
        human_headers = self._generate_human_headers()
        session.headers.update(human_headers)
        
        try:
            # Fazer requisição principal
            response = session.get(request_info['url'], timeout=15)
            
            # Simular ações humanas pós-request
            if response.status_code == 200:
                self._simulate_page_interaction(session, target, response)
                
        except Exception as e:
            self.logger.debug(f"Erro na simulação de navegação: {e}")
    
    def _generate_human_headers(self) -> Dict[str, str]:
        """
        Gera headers que simulam navegador humano
        """
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'pt-BR,pt;q=0.8,en;q=0.6', 'es-ES,es;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Headers opcionais realistas
        optional_headers = {
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        }
        
        # Adicionar alguns headers opcionais aleatoriamente
        for header, value in optional_headers.items():
            if random.random() < 0.7:  # 70% chance
                headers[header] = value
        
        return headers
    
    def _simulate_page_interaction(self, session: requests.Session, target: str, response: requests.Response):
        """
        Simula interação humana com a página
        """
        try:
            # Simular carregamento de recursos (CSS, JS, imagens)
            if random.random() < 0.8:  # 80% chance de carregar recursos
                self._simulate_resource_loading(session, target, response.text)
            
            # Simular tempo de leitura
            reading_time = random.uniform(2.0, 8.0)
            time.sleep(reading_time)
            
            # Simular cliques/navegação adicional
            if random.random() < 0.3:  # 30% chance de navegação adicional
                self._simulate_additional_navigation(session, target)
                
        except Exception as e:
            self.logger.debug(f"Erro na simulação de interação: {e}")
    
    def _simulate_resource_loading(self, session: requests.Session, target: str, html_content: str):
        """
        Simula carregamento de recursos da página
        """
        import re
        
        # Encontrar links para recursos
        css_links = re.findall(r'href=["\']([^"\']*\.css[^"\']*)["\']', html_content)
        js_links = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html_content)
        img_links = re.findall(r'src=["\']([^"\']*\.(jpg|jpeg|png|gif|svg)[^"\']*)["\']', html_content)
        
        all_resources = css_links + js_links + [img[0] for img in img_links]
        
        # Carregar alguns recursos aleatoriamente
        resources_to_load = random.sample(all_resources, min(3, len(all_resources)))
        
        for resource in resources_to_load:
            try:
                if resource.startswith('http'):
                    resource_url = resource
                else:
                    resource_url = f"http://{target}{resource}"
                
                session.get(resource_url, timeout=5)
                time.sleep(random.uniform(0.1, 0.5))  # Delay entre recursos
                
            except Exception:
                pass  # Ignorar erros de recursos
    
    def _simulate_additional_navigation(self, session: requests.Session, target: str):
        """
        Simula navegação adicional no site
        """
        common_pages = [
            '/about', '/contact', '/services', '/products', '/blog',
            '/login', '/register', '/help', '/support', '/faq'
        ]
        
        page = random.choice(common_pages)
        try:
            session.get(f"http://{target}{page}", timeout=10)
        except Exception:
            pass
    
    def anti_detection_techniques(self, target: str) -> Dict[str, Any]:
        """
        Aplica técnicas anti-detecção avançadas
        """
        self.logger.info(f"🥷 Aplicando técnicas anti-detecção para {target}")
        
        techniques = {
            'ip_rotation': self._setup_ip_rotation(),
            'traffic_fragmentation': self._setup_traffic_fragmentation(),
            'timing_randomization': self._setup_timing_randomization(),
            'protocol_evasion': self._setup_protocol_evasion(),
            'decoy_traffic': self._setup_decoy_traffic(target),
            'fingerprint_spoofing': self._setup_fingerprint_spoofing()
        }
        
        return techniques
    
    def _setup_ip_rotation(self) -> Dict[str, Any]:
        """
        Configura rotação de IP
        """
        return {
            'technique': 'IP Rotation',
            'description': 'Rotação de endereços IP via proxies/VPN',
            'status': 'configured',
            'proxies_available': len(self.proxy_pools),
            'rotation_interval': random.randint(10, 30)
        }
    
    def _setup_traffic_fragmentation(self) -> Dict[str, Any]:
        """
        Configura fragmentação de tráfego
        """
        return {
            'technique': 'Traffic Fragmentation',
            'description': 'Fragmentação de requests para evadir DPI',
            'status': 'enabled',
            'fragment_size': random.randint(64, 256),
            'fragmentation_delay': random.uniform(0.1, 0.5)
        }
    
    def _setup_timing_randomization(self) -> Dict[str, Any]:
        """
        Configura randomização de timing
        """
        return {
            'technique': 'Timing Randomization',
            'description': 'Padrões de timing aleatórios para evadir detecção comportamental',
            'status': 'active',
            'base_delay': random.uniform(1.0, 3.0),
            'jitter_factor': random.uniform(0.3, 0.8),
            'pattern': random.choice(list(self.human_timing_patterns.keys()))
        }
    
    def _setup_protocol_evasion(self) -> Dict[str, Any]:
        """
        Configura evasão de protocolo
        """
        return {
            'technique': 'Protocol Evasion',
            'description': 'Evasão via manipulação de protocolos',
            'status': 'configured',
            'methods': ['HTTP/2', 'WebSocket', 'QUIC'],
            'header_manipulation': True,
            'compression_evasion': True
        }
    
    def _setup_decoy_traffic(self, target: str) -> Dict[str, Any]:
        """
        Configura tráfego chamariz
        """
        return {
            'technique': 'Decoy Traffic',
            'description': 'Tráfego falso para confundir sistemas de detecção',
            'status': 'generating',
            'decoy_ratio': random.uniform(0.3, 0.7),  # 30-70% de tráfego falso
            'decoy_targets': self._generate_decoy_targets(target),
            'legitimate_mimicry': True
        }
    
    def _generate_decoy_targets(self, real_target: str) -> List[str]:
        """
        Gera alvos chamariz para confundir detecção
        """
        decoy_domains = [
            'google.com', 'microsoft.com', 'amazon.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'news.ycombinator.com'
        ]
        
        # Misturar alvos reais com chamariz
        return random.sample(decoy_domains, 3)
    
    def _setup_fingerprint_spoofing(self) -> Dict[str, Any]:
        """
        Configura spoofing de fingerprint
        """
        return {
            'technique': 'Fingerprint Spoofing',
            'description': 'Spoofing de fingerprints TLS/HTTP/TCP',
            'status': 'active',
            'tls_fingerprint': self._generate_fake_tls_fingerprint(),
            'http_fingerprint': self._generate_fake_http_fingerprint(),
            'tcp_options': self._generate_fake_tcp_options()
        }
    
    def _generate_fake_tls_fingerprint(self) -> str:
        """
        Gera fingerprint TLS falso
        """
        # Fingerprints TLS comuns de browsers reais
        common_fingerprints = [
            '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53',
            '772,4865-4866-4867-49195-49199-52393-52392-49171-49172-156-157-47-53-10',
            '769,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53'
        ]
        
        return random.choice(common_fingerprints)
    
    def _generate_fake_http_fingerprint(self) -> str:
        """
        Gera fingerprint HTTP falso
        """
        return f"Browser-{random.randint(100, 999)}-{random.randint(10, 99)}"
    
    def _generate_fake_tcp_options(self) -> List[str]:
        """
        Gera opções TCP falsas
        """
        tcp_options = ['mss', 'wscale', 'timestamp', 'sackperm', 'nop']
        return random.sample(tcp_options, random.randint(2, 4))
    
    def create_stealth_session(self, stealth_config: Dict[str, Any]) -> requests.Session:
        """
        Cria sessão HTTP configurada para stealth
        """
        session = requests.Session()
        session.verify = False
        
        # Configurar headers stealth
        session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
        })
        
        # Configurar timeouts baseados no modo stealth
        if stealth_config.get('stealth_level') == 'maximum':
            session.timeout = 60
        else:
            session.timeout = 30
        
        # Configurar proxies se disponível
        if stealth_config.get('rotate_proxies') and self.proxy_pools:
            proxy = random.choice(self.proxy_pools)
            session.proxies = proxy
        
        return session