#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo OSINT Reconnaissance
Reconhecimento passivo para coleta de inteligência de fontes abertas
"""

import requests
import dns.resolver
import json
import time
import random
import logging
import socket
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
import subprocess
import re

class OSINTReconnaissance:
    """
    Módulo para reconhecimento OSINT (Open Source Intelligence)
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def comprehensive_osint_scan(self, target: str) -> Dict[str, Any]:
        """
        Executa reconhecimento OSINT completo
        """
        self.logger.info(f"🕵️ Iniciando reconhecimento OSINT para {target}")
        
        osint_results = {
            'target': target,
            'timestamp': time.time(),
            'domain_info': {},
            'subdomains': [],
            'dns_records': {},
            'whois_info': {},
            'social_media': {},
            'email_addresses': [],
            'exposed_files': [],
            'technology_stack': {},
            'certificates': {},
            'vulnerabilities_db': [],
            'dark_web_mentions': [],
            'pastebins': [],
            'github_leaks': []
        }
        
        # Reconhecimento de domínio
        osint_results['domain_info'] = self._domain_reconnaissance(target)
        
        # Enumeração de subdomínios
        osint_results['subdomains'] = self._subdomain_enumeration(target)
        
        # Análise DNS
        osint_results['dns_records'] = self._dns_analysis(target)
        
        # Informações WHOIS
        osint_results['whois_info'] = self._whois_analysis(target)
        
        # Busca por mídias sociais
        osint_results['social_media'] = self._social_media_search(target)
        
        # Busca por emails
        osint_results['email_addresses'] = self._email_harvesting(target)
        
        # Arquivos expostos
        osint_results['exposed_files'] = self._file_exposure_scan(target)
        
        # Stack tecnológico
        osint_results['technology_stack'] = self._technology_fingerprinting(target)
        
        # Análise de certificados
        osint_results['certificates'] = self._certificate_analysis(target)
        
        # Busca em bases de vulnerabilidades
        osint_results['vulnerabilities_db'] = self._vulnerability_database_search(target)
        
        # Busca em pastebins
        osint_results['pastebins'] = self._pastebin_search(target)
        
        # Busca no GitHub
        osint_results['github_leaks'] = self._github_reconnaissance(target)
        
        return osint_results
    
    def _domain_reconnaissance(self, target: str) -> Dict[str, Any]:
        """
        Reconhecimento básico de domínio
        """
        self.logger.info(f"🌐 Analisando domínio {target}")
        
        domain_info = {
            'domain': target,
            'ip_addresses': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'geolocation': {},
            'registrar': '',
            'creation_date': '',
            'expiration_date': ''
        }
        
        try:
            # Resolver IPs
            ip_addresses = socket.gethostbyname_ex(target)[2]
            domain_info['ip_addresses'] = ip_addresses
            
            # Geolocalização (simulada)
            if ip_addresses:
                domain_info['geolocation'] = self._simulate_geolocation(ip_addresses[0])
                
        except Exception as e:
            self.logger.debug(f"Erro na resolução DNS: {e}")
        
        return domain_info
    
    def _subdomain_enumeration(self, target: str) -> List[str]:
        """
        Enumeração de subdomínios
        """
        self.logger.info(f"🔍 Enumerando subdomínios de {target}")
        
        subdomains = []
        
        # Lista de subdomínios comuns
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'sslvpn', 'test', 'portal',
            'api', 'app', 'dev', 'staging', 'prod', 'ftp', 'mobile', 'shop',
            'support', 'help', 'docs', 'cdn', 'media', 'static', 'assets',
            'beta', 'alpha', 'demo', 'sandbox', 'login', 'auth', 'sso',
            'monitoring', 'metrics', 'logs', 'status', 'health', 'backup'
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{target}"
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                self.logger.info(f"✅ Subdomínio encontrado: {full_domain}")
                
                # Delay para evitar rate limiting
                time.sleep(random.uniform(0.1, 0.5))
                
            except socket.gaierror:
                pass
            except Exception as e:
                self.logger.debug(f"Erro ao verificar {subdomain}.{target}: {e}")
        
        return subdomains
    
    def _dns_analysis(self, target: str) -> Dict[str, List]:
        """
        Análise detalhada de registros DNS
        """
        self.logger.info(f"🗂️ Analisando registros DNS de {target}")
        
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': [],
            'PTR': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(target, record_type)
                for answer in answers:
                    dns_records[record_type].append(str(answer))
                    
            except Exception as e:
                self.logger.debug(f"Erro ao obter registro {record_type}: {e}")
        
        return dns_records
    
    def _whois_analysis(self, target: str) -> Dict[str, Any]:
        """
        Análise WHOIS detalhada
        """
        self.logger.info(f"📋 Executando análise WHOIS de {target}")
        
        whois_info = {
            'domain': target,
            'registrar': '',
            'creation_date': '',
            'expiration_date': '',
            'name_servers': [],
            'registrant': {},
            'admin_contact': {},
            'tech_contact': {},
            'status': []
        }
        
        try:
            # Executar comando whois
            result = subprocess.run(['whois', target], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=30)
            
            whois_output = result.stdout
            
            # Parser simples para extrair informações chave
            patterns = {
                'registrar': r'Registrar:\s*(.+)',
                'creation_date': r'Creation Date:\s*(.+)',
                'expiration_date': r'Expir\w*\s*Date:\s*(.+)',
                'name_server': r'Name Server:\s*(.+)',
            }
            
            for field, pattern in patterns.items():
                matches = re.findall(pattern, whois_output, re.IGNORECASE)
                if matches:
                    if field == 'name_server':
                        whois_info['name_servers'] = matches
                    else:
                        whois_info[field] = matches[0].strip()
                        
        except Exception as e:
            self.logger.debug(f"Erro na análise WHOIS: {e}")
        
        return whois_info
    
    def _social_media_search(self, target: str) -> Dict[str, List]:
        """
        Busca por presenças em mídias sociais
        """
        self.logger.info(f"📱 Buscando mídias sociais relacionadas a {target}")
        
        social_media = {
            'twitter': [],
            'linkedin': [],
            'facebook': [],
            'instagram': [],
            'github': [],
            'youtube': []
        }
        
        # Buscar perfis relacionados ao domínio
        domain_name = target.replace('.com', '').replace('.org', '').replace('.net', '')
        
        social_platforms = {
            'twitter': f'https://twitter.com/{domain_name}',
            'linkedin': f'https://linkedin.com/company/{domain_name}',
            'facebook': f'https://facebook.com/{domain_name}',
            'instagram': f'https://instagram.com/{domain_name}',
            'github': f'https://github.com/{domain_name}',
            'youtube': f'https://youtube.com/user/{domain_name}'
        }
        
        for platform, url in social_platforms.items():
            try:
                response = self.session.head(url, timeout=10)
                if response.status_code == 200:
                    social_media[platform].append(url)
                    self.logger.info(f"📱 Perfil encontrado: {url}")
                    
            except Exception as e:
                self.logger.debug(f"Erro ao verificar {platform}: {e}")
        
        return social_media
    
    def _email_harvesting(self, target: str) -> List[str]:
        """
        Coleta de endereços de email
        """
        self.logger.info(f"📧 Coletando emails relacionados a {target}")
        
        emails = []
        
        # Padrões de email comuns
        common_patterns = [
            f'admin@{target}',
            f'info@{target}',
            f'contact@{target}',
            f'support@{target}',
            f'sales@{target}',
            f'security@{target}',
            f'webmaster@{target}',
            f'noreply@{target}',
            f'marketing@{target}',
            f'hr@{target}'
        ]
        
        emails.extend(common_patterns)
        
        # Buscar emails no site principal
        try:
            response = self.session.get(f'http://{target}', timeout=10)
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            found_emails = re.findall(email_pattern, response.text)
            
            for email in found_emails:
                if email not in emails:
                    emails.append(email)
                    self.logger.info(f"📧 Email encontrado: {email}")
                    
        except Exception as e:
            self.logger.debug(f"Erro na coleta de emails: {e}")
        
        return emails
    
    def _file_exposure_scan(self, target: str) -> List[Dict]:
        """
        Busca por arquivos expostos
        """
        self.logger.info(f"📁 Verificando arquivos expostos em {target}")
        
        exposed_files = []
        
        # Arquivos sensíveis comuns
        sensitive_files = [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            '.git/config',
            '.env',
            'config.php',
            'database.sql',
            'backup.sql',
            'phpinfo.php',
            'admin.php',
            'login.php',
            'test.php',
            'debug.log',
            'error.log',
            'access.log',
            'wp-config.php',
            '.DS_Store',
            'thumbs.db'
        ]
        
        for file in sensitive_files:
            try:
                url = f'http://{target}/{file}'
                response = self.session.head(url, timeout=5)
                
                if response.status_code == 200:
                    file_info = {
                        'file': file,
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        'size': response.headers.get('Content-Length', 'unknown')
                    }
                    exposed_files.append(file_info)
                    self.logger.warning(f"📁 Arquivo exposto: {url}")
                    
            except Exception as e:
                self.logger.debug(f"Erro ao verificar {file}: {e}")
        
        return exposed_files
    
    def _technology_fingerprinting(self, target: str) -> Dict[str, Any]:
        """
        Fingerprinting de tecnologias
        """
        self.logger.info(f"🔧 Identificando tecnologias em {target}")
        
        tech_stack = {
            'web_server': '',
            'programming_language': '',
            'framework': '',
            'cms': '',
            'javascript_libraries': [],
            'css_frameworks': [],
            'analytics': [],
            'security': []
        }
        
        try:
            response = self.session.get(f'http://{target}', timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # Identificar servidor web
            server = headers.get('Server', '')
            if 'nginx' in server.lower():
                tech_stack['web_server'] = 'Nginx'
            elif 'apache' in server.lower():
                tech_stack['web_server'] = 'Apache'
            elif 'iis' in server.lower():
                tech_stack['web_server'] = 'IIS'
            
            # Identificar linguagem de programação
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by'].lower()
                if 'php' in powered_by:
                    tech_stack['programming_language'] = 'PHP'
                elif 'asp.net' in powered_by:
                    tech_stack['programming_language'] = 'ASP.NET'
            
            # Identificar CMS
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
                'drupal': ['drupal', '/sites/default/', 'drupal.js'],
                'joomla': ['joomla', '/administrator/', 'joomla.js'],
                'magento': ['magento', 'mage/cookies', 'varien/js']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    tech_stack['cms'] = cms.title()
                    break
            
            # Identificar bibliotecas JavaScript
            js_libraries = {
                'jquery': 'jquery',
                'bootstrap': 'bootstrap',
                'angular': 'angular',
                'react': 'react',
                'vue': 'vue.js'
            }
            
            for lib, signature in js_libraries.items():
                if signature in content:
                    tech_stack['javascript_libraries'].append(lib)
            
            # Identificar ferramentas de analytics
            analytics_tools = {
                'google_analytics': 'google-analytics.com',
                'gtag': 'gtag(',
                'facebook_pixel': 'facebook.net/tr'
            }
            
            for tool, signature in analytics_tools.items():
                if signature in content:
                    tech_stack['analytics'].append(tool)
                    
        except Exception as e:
            self.logger.debug(f"Erro no fingerprinting: {e}")
        
        return tech_stack
    
    def _certificate_analysis(self, target: str) -> Dict[str, Any]:
        """
        Análise de certificados SSL/TLS
        """
        self.logger.info(f"🔒 Analisando certificados SSL de {target}")
        
        cert_info = {
            'has_ssl': False,
            'issuer': '',
            'subject': '',
            'valid_from': '',
            'valid_to': '',
            'serial_number': '',
            'signature_algorithm': '',
            'san_domains': []
        }
        
        try:
            # Tentar conexão SSL
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info['has_ssl'] = True
                    cert_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    cert_info['subject'] = dict(x[0] for x in cert['subject'])
                    cert_info['valid_from'] = cert['notBefore']
                    cert_info['valid_to'] = cert['notAfter']
                    cert_info['serial_number'] = cert['serialNumber']
                    
                    # Subject Alternative Names
                    if 'subjectAltName' in cert:
                        cert_info['san_domains'] = [x[1] for x in cert['subjectAltName']]
                        
        except Exception as e:
            self.logger.debug(f"Erro na análise de certificado: {e}")
        
        return cert_info
    
    def _vulnerability_database_search(self, target: str) -> List[Dict]:
        """
        Busca em bases de dados de vulnerabilidades
        """
        self.logger.info(f"🔍 Buscando vulnerabilidades conhecidas para {target}")
        
        vulnerabilities = []
        
        # Simular busca em bases de dados
        # Em implementação real, consultaria:
        # - CVE databases
        # - Exploit-DB
        # - Vulnerability scanners APIs
        # - Security advisories
        
        mock_vulnerabilities = [
            {
                'cve_id': 'CVE-2024-XXXX',
                'description': 'Simulated vulnerability found in database',
                'severity': 'HIGH',
                'cvss_score': 7.5,
                'published_date': '2024-01-15',
                'source': 'Mock Database'
            }
        ]
        
        # Retornar vulnerabilidades mockadas para demonstração
        vulnerabilities.extend(mock_vulnerabilities)
        
        return vulnerabilities
    
    def _pastebin_search(self, target: str) -> List[Dict]:
        """
        Busca em pastebins por vazamentos
        """
        self.logger.info(f"📋 Buscando vazamentos em pastebins para {target}")
        
        pastebins = []
        
        # Simular busca em pastebins
        # Em implementação real, consultaria:
        # - Pastebin.com
        # - Hastebin
        # - GitHub Gists
        # - Outras plataformas de paste
        
        mock_pastes = [
            {
                'title': f'Configuration file for {target}',
                'url': 'https://pastebin.com/XXXXXXXX',
                'content_preview': 'database_password=secret123',
                'date': '2024-01-01',
                'risk_level': 'HIGH'
            }
        ]
        
        pastebins.extend(mock_pastes)
        
        return pastebins
    
    def _github_reconnaissance(self, target: str) -> List[Dict]:
        """
        Reconhecimento no GitHub
        """
        self.logger.info(f"👨‍💻 Buscando informações no GitHub para {target}")
        
        github_results = []
        
        # Simular busca no GitHub
        # Em implementação real, usaria GitHub API para:
        # - Buscar repositórios relacionados
        # - Procurar por credenciais vazadas
        # - Identificar desenvolvedores
        # - Analisar commits
        
        mock_repos = [
            {
                'repository': f'{target}-config',
                'url': f'https://github.com/example/{target}-config',
                'description': 'Configuration files',
                'last_updated': '2024-01-01',
                'sensitive_files': ['config.json', 'database.yml'],
                'risk_level': 'MEDIUM'
            }
        ]
        
        github_results.extend(mock_repos)
        
        return github_results
    
    def _simulate_geolocation(self, ip: str) -> Dict[str, str]:
        """
        Simula geolocalização de IP
        """
        # Em implementação real, usaria serviços como MaxMind, IPStack, etc.
        mock_geo = {
            'country': 'United States',
            'city': 'San Francisco',
            'region': 'California',
            'latitude': '37.7749',
            'longitude': '-122.4194',
            'isp': 'Example ISP',
            'organization': 'Example Org'
        }
        
        return mock_geo