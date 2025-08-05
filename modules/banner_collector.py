#!/usr/bin/env python3
"""
Módulo Banner Collector
Responsável por coleta ativa de banners de serviços expostos
"""

import socket
import ssl
import requests
import subprocess
import re
from typing import Dict, List
from urllib.parse import urlparse
import concurrent.futures
import time
# Suprimir warnings SSL para ferramentas de pentest
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass  # urllib3 warnings são opcionais

class BannerCollector:
    """Coletor de banners para identificação de serviços expostos"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.timeout = 5
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Portas comuns para coleta de banner
        self.common_ports = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            135: 'rpc',
            139: 'netbios',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            8080: 'http-alt',
            8443: 'https-alt'
        }
    
    def collect_banners(self, target: str) -> Dict:
        """Coleta banners de todos os serviços disponíveis"""
        results = {
            'target': target,
            'banners': {},
            'web_banners': {},
            'exposed_services': [],
            'sensitive_info': [],
            'total_services_found': 0
        }
        
        try:
            # 1. Scan de portas ativas primeiro
            active_ports = self._discover_active_ports(target)
            
            # 2. Coleta de banners de serviços de rede
            network_banners = self._collect_network_banners(target, active_ports)
            results['banners'] = network_banners
            
            # 3. Coleta específica de banners web
            web_banners = self._collect_web_banners(target)
            results['web_banners'] = web_banners
            
            # 4. Análise de serviços expostos
            results['exposed_services'] = self._analyze_exposed_services(network_banners, web_banners)
            
            # 5. Detecção de informações sensíveis
            results['sensitive_info'] = self._detect_sensitive_info(network_banners, web_banners)
            
            results['total_services_found'] = len(network_banners) + len(web_banners)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro na coleta de banners de {target}: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _discover_active_ports(self, target: str) -> List[int]:
        """Descobre portas ativas rapidamente"""
        active_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Usar threading para acelerar o processo
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, port) for port in self.common_ports.keys()]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    active_ports.append(result)
        
        return sorted(active_ports)
    
    def _collect_network_banners(self, target: str, ports: List[int]) -> Dict:
        """Coleta banners de serviços de rede"""
        banners = {}
        
        for port in ports:
            try:
                service = self.common_ports.get(port, 'unknown')
                banner = None
                
                if service in ['http', 'https', 'http-alt', 'https-alt']:
                    # Banners web são tratados separadamente
                    continue
                elif service == 'ssh':
                    banner = self._collect_ssh_banner(target, port)
                elif service == 'ftp':
                    banner = self._collect_ftp_banner(target, port)
                elif service == 'smtp':
                    banner = self._collect_smtp_banner(target, port)
                elif service == 'telnet':
                    banner = self._collect_telnet_banner(target, port)
                else:
                    # Banner genérico
                    banner = self._collect_generic_banner(target, port)
                
                if banner:
                    banners[port] = {
                        'service': service,
                        'banner': banner,
                        'risk_level': self._assess_banner_risk(banner, service)
                    }
                    
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro coletando banner da porta {port}: {str(e)}")
                continue
        
        return banners
    
    def _collect_ssh_banner(self, target: str, port: int) -> str:
        """Coleta banner SSH"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception:
            return None
    
    def _collect_ftp_banner(self, target: str, port: int) -> str:
        """Coleta banner FTP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception:
            return None
    
    def _collect_smtp_banner(self, target: str, port: int) -> str:
        """Coleta banner SMTP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Enviar EHLO para obter mais informações
            sock.send(b'EHLO test\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            
            return f"{banner}\n{response}"
            
        except Exception:
            return None
    
    def _collect_telnet_banner(self, target: str, port: int) -> str:
        """Coleta banner Telnet"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            time.sleep(1)  # Aguardar banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception:
            return None
    
    def _collect_generic_banner(self, target: str, port: int) -> str:
        """Coleta banner genérico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Tentar receber dados
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Se não recebeu nada, tentar enviar algo genérico
            if not banner:
                sock.send(b'\r\n')
                time.sleep(1)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def _collect_web_banners(self, target: str) -> Dict:
        """Coleta banners específicos de serviços web"""
        web_banners = {}
        web_ports = [80, 443, 8080, 8443]
        
        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{target}:{port}"
                
                banner_info = self._collect_http_banner(url)
                if banner_info:
                    web_banners[port] = banner_info
                    
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro coletando banner web da porta {port}: {str(e)}")
                continue
        
        return web_banners
    
    def _collect_http_banner(self, url: str) -> Dict:
        """Coleta banners HTTP/HTTPS"""
        try:
            headers = {'User-Agent': self.user_agent}
            
            # Request com timeout
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            
            banner_info = {
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'technology': response.headers.get('X-Technology', ''),
                'status_code': response.status_code,
                'title': self._extract_title(response.text),
                'headers': dict(response.headers),
                'cookies': [cookie.name for cookie in response.cookies],
                'security_headers': self._check_security_headers(response.headers),
                'detected_tech': self._detect_technologies(response.text, response.headers)
            }
            
            return banner_info
            
        except Exception:
            return None
    
    def _extract_title(self, html_content: str) -> str:
        """Extrai título da página HTML"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]  # Limitar tamanho
        except:
            pass
        return ""
    
    def _check_security_headers(self, headers: Dict) -> Dict:
        """Verifica presença de headers de segurança"""
        security_headers = {
            'strict-transport-security': headers.get('Strict-Transport-Security'),
            'content-security-policy': headers.get('Content-Security-Policy'),
            'x-frame-options': headers.get('X-Frame-Options'),
            'x-content-type-options': headers.get('X-Content-Type-Options'),
            'x-xss-protection': headers.get('X-XSS-Protection')
        }
        
        return {k: v for k, v in security_headers.items() if v}
    
    def _detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Detecta tecnologias baseado no conteúdo"""
        technologies = []
        
        # Patterns para detecção de tecnologias
        tech_patterns = {
            'WordPress': [r'wp-content', r'wordpress'],
            'Drupal': [r'drupal', r'sites/default'],
            'Joomla': [r'joomla', r'option=com_'],
            'Apache': [r'Apache', r'httpd'],
            'Nginx': [r'nginx'],
            'IIS': [r'Microsoft-IIS'],
            'PHP': [r'\.php', r'X-Powered-By.*PHP'],
            'ASP.NET': [r'asp\.net', r'__VIEWSTATE'],
            'jQuery': [r'jquery'],
            'Bootstrap': [r'bootstrap']
        }
        
        content_lower = content.lower()
        headers_str = str(headers).lower()
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE) or re.search(pattern, headers_str, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        return list(set(technologies))
    
    def _analyze_exposed_services(self, network_banners: Dict, web_banners: Dict) -> List[str]:
        """Analisa serviços expostos e potencialmente perigosos"""
        exposed_services = []
        
        # Analisar banners de rede
        for port, banner_data in network_banners.items():
            banner = banner_data.get('banner', '')
            service = banner_data.get('service', '')
            
            # Detectar versões específicas
            if 'ssh' in service.lower() and banner:
                exposed_services.append(f"SSH exposto na porta {port}: {banner[:50]}...")
            
            if 'ftp' in service.lower() and banner:
                exposed_services.append(f"FTP exposto na porta {port}: {banner[:50]}...")
            
            if 'telnet' in service.lower():
                exposed_services.append(f"TELNET exposto na porta {port} - ALTO RISCO")
            
            if 'smtp' in service.lower() and banner:
                exposed_services.append(f"SMTP exposto na porta {port}: {banner[:50]}...")
        
        # Analisar banners web
        for port, web_data in web_banners.items():
            server = web_data.get('server', '')
            powered_by = web_data.get('powered_by', '')
            
            if server:
                exposed_services.append(f"Servidor web na porta {port}: {server}")
            
            if powered_by:
                exposed_services.append(f"Tecnologia web na porta {port}: {powered_by}")
            
            # Verificar tecnologias detectadas
            for tech in web_data.get('detected_tech', []):
                exposed_services.append(f"Tecnologia detectada na porta {port}: {tech}")
        
        return exposed_services
    
    def _detect_sensitive_info(self, network_banners: Dict, web_banners: Dict) -> List[str]:
        """Detecta informações sensíveis nos banners"""
        sensitive_info = []
        
        # Palavras-chave sensíveis
        sensitive_keywords = [
            'admin', 'administrator', 'root', 'password', 'login',
            'default', 'test', 'demo', 'guest', 'user',
            'version', 'server', 'system', 'os', 'kernel'
        ]
        
        # Analisar banners de rede
        for port, banner_data in network_banners.items():
            banner = banner_data.get('banner', '').lower()
            
            for keyword in sensitive_keywords:
                if keyword in banner:
                    sensitive_info.append(f"Informação sensível na porta {port}: {keyword}")
        
        # Analisar banners web
        for port, web_data in web_banners.items():
            # Verificar headers sensíveis
            headers = web_data.get('headers', {})
            
            for header, value in headers.items():
                header_lower = header.lower()
                value_lower = str(value).lower()
                
                if any(keyword in value_lower for keyword in sensitive_keywords):
                    sensitive_info.append(f"Header sensível na porta {port}: {header} = {value}")
            
            # Verificar se não tem headers de segurança
            security_headers = web_data.get('security_headers', {})
            if not security_headers:
                sensitive_info.append(f"Ausência de headers de segurança na porta {port}")
        
        return list(set(sensitive_info))
    
    def _assess_banner_risk(self, banner: str, service: str) -> str:
        """Avalia o risco do banner coletado"""
        if not banner:
            return "LOW"
        
        banner_lower = banner.lower()
        
        # Alto risco
        high_risk_indicators = ['telnet', 'default', 'admin', 'root', 'password']
        if any(indicator in banner_lower for indicator in high_risk_indicators):
            return "HIGH"
        
        # Médio risco
        medium_risk_indicators = ['version', 'server', 'system']
        if any(indicator in banner_lower for indicator in medium_risk_indicators):
            return "MEDIUM"
        
        return "LOW"
