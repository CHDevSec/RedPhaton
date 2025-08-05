#!/usr/bin/env python3
"""
Módulo Footprint Analyzer
Responsável por análise de footprint e correlação de dados coletados
"""

import re
from typing import Dict, List
from datetime import datetime

class FootprintAnalyzer:
    """Analisador de footprint para correlação e análise de dados"""
    
    def __init__(self, logger=None):
        self.logger = logger
        
        # Vulnerabilidades conhecidas básicas
        self.known_vulnerabilities = {
            'OpenSSH': {
                '7.4': ['CVE-2018-15473'],
                '6.6': ['CVE-2016-0777'],
            },
            'Apache': {
                '2.4.29': ['CVE-2017-15710'],
                '2.2.34': ['CVE-2017-3167']
            }
        }
    
    def analyze_target(self, target: str, nmap_data: Dict, banner_data: Dict) -> Dict:
        """Realiza análise completa de footprint do alvo"""
        analysis = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'attack_surface': {},
            'technology_stack': {},
            'security_posture': {},
            'vulnerability_assessment': {},
            'recommendations': [],
            'threat_level': 'LOW'
        }
        
        try:
            # 1. Análise da superfície de ataque
            analysis['attack_surface'] = self._analyze_attack_surface(nmap_data, banner_data)
            
            # 2. Identificação do stack tecnológico
            analysis['technology_stack'] = self._identify_technology_stack(banner_data)
            
            # 3. Avaliação da postura de segurança
            analysis['security_posture'] = self._assess_security_posture(nmap_data, banner_data)
            
            # 4. Avaliação de vulnerabilidades
            analysis['vulnerability_assessment'] = self._assess_vulnerabilities(
                analysis['technology_stack'], banner_data
            )
            
            # 5. Gerar recomendações
            analysis['recommendations'] = self._generate_recommendations(analysis)
            
            # 6. Calcular nível de ameaça
            analysis['threat_level'] = self._calculate_threat_level(analysis)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro na análise de footprint de {target}: {str(e)}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_attack_surface(self, nmap_data: Dict, banner_data: Dict) -> Dict:
        """Analisa a superfície de ataque disponível"""
        attack_surface = {
            'open_ports': [],
            'exposed_services': [],
            'web_interfaces': [],
            'admin_interfaces': [],
            'total_exposure_score': 0
        }
        
        # Analisar portas abertas do Nmap
        if 'open_ports' in nmap_data:
            attack_surface['open_ports'] = nmap_data['open_ports']
        
        # Analisar serviços expostos
        if 'services' in nmap_data:
            for port, service_info in nmap_data['services'].items():
                service_name = service_info.get('service', 'unknown')
                version = service_info.get('version', '')
                
                attack_surface['exposed_services'].append({
                    'port': port,
                    'service': service_name,
                    'version': version,
                    'risk_level': self._assess_service_risk(service_name, version)
                })
        
        # Analisar interfaces web
        if 'web_banners' in banner_data:
            for port, web_info in banner_data['web_banners'].items():
                title = web_info.get('title', '')
                server = web_info.get('server', '')
                
                attack_surface['web_interfaces'].append({
                    'port': port,
                    'title': title,
                    'server': server,
                    'is_admin': self._is_admin_interface(title, web_info)
                })
                
                # Detectar interfaces administrativas
                if self._is_admin_interface(title, web_info):
                    attack_surface['admin_interfaces'].append({
                        'port': port,
                        'title': title,
                        'type': self._detect_admin_type(title, web_info)
                    })
        
        # Calcular score de exposição
        attack_surface['total_exposure_score'] = self._calculate_exposure_score(attack_surface)
        
        return attack_surface
    
    def _identify_technology_stack(self, banner_data: Dict) -> Dict:
        """Identifica o stack tecnológico do alvo"""
        tech_stack = {
            'web_server': [],
            'cms': [],
            'frameworks': [],
            'databases': [],
            'programming_languages': [],
            'operating_system': []
        }
        
        # Analisar banners de rede
        if 'banners' in banner_data:
            for port, banner_info in banner_data['banners'].items():
                banner = banner_info.get('banner', '')
                service = banner_info.get('service', '')
                
                # Identificar OS
                os_info = self._detect_os_from_banner(banner)
                if os_info:
                    tech_stack['operating_system'].append(os_info)
                
                # Identificar bancos de dados
                if service in ['mysql', 'postgresql', 'mongodb', 'mssql']:
                    version = self._extract_version_from_banner(banner)
                    tech_stack['databases'].append({
                        'type': service,
                        'version': version,
                        'port': port
                    })
        
        # Analisar banners web
        if 'web_banners' in banner_data:
            for port, web_info in banner_data['web_banners'].items():
                server = web_info.get('server', '')
                powered_by = web_info.get('powered_by', '')
                detected_tech = web_info.get('detected_tech', [])
                
                # Web server
                if server:
                    tech_stack['web_server'].append({
                        'type': self._extract_server_type(server),
                        'version': self._extract_version_from_banner(server),
                        'port': port
                    })
                
                # Linguagens de programação
                if powered_by:
                    lang = self._detect_programming_language(powered_by)
                    if lang:
                        tech_stack['programming_languages'].append(lang)
                
                # Tecnologias detectadas
                for tech in detected_tech:
                    category = self._categorize_technology(tech)
                    if category and category in tech_stack:
                        tech_stack[category].append(tech)
        
        return tech_stack
    
    def _assess_security_posture(self, nmap_data: Dict, banner_data: Dict) -> Dict:
        """Avalia a postura de segurança do alvo"""
        security_posture = {
            'security_headers': {},
            'encryption_status': {},
            'access_controls': {},
            'information_disclosure': [],
            'security_score': 0,
            'critical_issues': []
        }
        
        # Analisar headers de segurança
        if 'web_banners' in banner_data:
            for port, web_info in banner_data['web_banners'].items():
                security_headers = web_info.get('security_headers', {})
                
                if security_headers:
                    security_posture['security_headers'][port] = security_headers
                else:
                    security_posture['critical_issues'].append(
                        f"Porta {port}: Ausência de headers de segurança"
                    )
        
        # Analisar criptografia
        security_posture['encryption_status'] = self._analyze_encryption(nmap_data, banner_data)
        
        # Detectar vazamento de informações
        security_posture['information_disclosure'] = self._detect_information_disclosure(banner_data)
        
        # Calcular score de segurança
        security_posture['security_score'] = self._calculate_security_score(security_posture)
        
        return security_posture
    
    def _assess_vulnerabilities(self, tech_stack: Dict, banner_data: Dict) -> Dict:
        """Avalia vulnerabilidades baseado no stack identificado"""
        vuln_assessment = {
            'known_vulnerabilities': [],
            'potential_vulnerabilities': [],
            'critical_services': [],
            'outdated_software': [],
            'risk_score': 0
        }
        
        # Verificar vulnerabilidades conhecidas
        for category, items in tech_stack.items():
            for item in items:
                if isinstance(item, dict):
                    software = item.get('type', '')
                    version = item.get('version', '')
                elif isinstance(item, str):
                    software = item
                    version = ''
                else:
                    continue
                
                # Buscar vulnerabilidades conhecidas
                vulns = self._lookup_vulnerabilities(software, version)
                if vulns:
                    vuln_assessment['known_vulnerabilities'].extend(vulns)
        
        # Identificar serviços críticos
        vuln_assessment['critical_services'] = self._identify_critical_services(banner_data)
        
        # Detectar software desatualizado
        vuln_assessment['outdated_software'] = self._detect_outdated_software(tech_stack)
        
        # Calcular score de risco
        vuln_assessment['risk_score'] = self._calculate_vulnerability_risk_score(vuln_assessment)
        
        return vuln_assessment
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Gera recomendações baseadas na análise"""
        recommendations = []
        
        # Recomendações baseadas na superfície de ataque
        attack_surface = analysis.get('attack_surface', {})
        if len(attack_surface.get('open_ports', [])) > 10:
            recommendations.append("Reduzir número de portas abertas - fechar serviços desnecessários")
        
        if attack_surface.get('admin_interfaces'):
            recommendations.append("Restringir acesso às interfaces administrativas via IP/VPN")
        
        # Recomendações de segurança
        security_posture = analysis.get('security_posture', {})
        if security_posture.get('security_score', 0) < 50:
            recommendations.append("Implementar headers de segurança HTTP")
            recommendations.append("Configurar HTTPS com certificados válidos")
        
        # Recomendações de vulnerabilidades
        vuln_assessment = analysis.get('vulnerability_assessment', {})
        if vuln_assessment.get('known_vulnerabilities'):
            recommendations.append("Aplicar patches de segurança para vulnerabilidades conhecidas")
        
        if vuln_assessment.get('outdated_software'):
            recommendations.append("Atualizar software para versões mais recentes")
        
        # Recomendações gerais
        recommendations.extend([
            "Implementar monitoramento de segurança contínuo",
            "Realizar testes de penetração regulares"
        ])
        
        return recommendations
    
    def _calculate_threat_level(self, analysis: Dict) -> str:
        """Calcula o nível de ameaça geral"""
        score = 0
        
        # Pontuação baseada na superfície de ataque
        attack_surface = analysis.get('attack_surface', {})
        score += attack_surface.get('total_exposure_score', 0) * 0.3
        
        # Pontuação baseada na postura de segurança
        security_posture = analysis.get('security_posture', {})
        security_score = security_posture.get('security_score', 100)
        score += (100 - security_score) * 0.4
        
        # Pontuação baseada em vulnerabilidades
        vuln_assessment = analysis.get('vulnerability_assessment', {})
        score += vuln_assessment.get('risk_score', 0) * 0.3
        
        # Determinar nível
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    # Métodos auxiliares
    def _assess_service_risk(self, service: str, version: str) -> str:
        """Avalia o risco de um serviço específico"""
        high_risk_services = ['telnet', 'ftp', 'smtp', 'pop3', 'imap']
        
        if service.lower() in high_risk_services:
            return "HIGH"
        elif service.lower() in ['ssh', 'http', 'https']:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _is_admin_interface(self, title: str, web_info: Dict) -> bool:
        """Detecta se é uma interface administrativa"""
        admin_indicators = [
            'admin', 'administration', 'dashboard', 'control panel',
            'management', 'login', 'cpanel', 'phpmyadmin', 'webmin'
        ]
        
        title_lower = title.lower()
        return any(indicator in title_lower for indicator in admin_indicators)
    
    def _detect_admin_type(self, title: str, web_info: Dict) -> str:
        """Detecta o tipo de interface administrativa"""
        title_lower = title.lower()
        
        if 'phpmyadmin' in title_lower:
            return "Database Administration"
        elif 'cpanel' in title_lower:
            return "Web Hosting Control Panel"
        elif 'webmin' in title_lower:
            return "System Administration"
        elif 'wordpress' in title_lower and 'admin' in title_lower:
            return "WordPress Admin"
        else:
            return "Generic Admin Interface"
    
    def _calculate_exposure_score(self, attack_surface: Dict) -> int:
        """Calcula score de exposição"""
        score = 0
        
        # Pontos por porta aberta
        score += len(attack_surface.get('open_ports', [])) * 2
        
        # Pontos por serviço exposto
        score += len(attack_surface.get('exposed_services', [])) * 3
        
        # Pontos por interface administrativa
        score += len(attack_surface.get('admin_interfaces', [])) * 10
        
        return min(score, 100)  # Máximo 100
    
    def _detect_os_from_banner(self, banner: str) -> str:
        """Detecta SO a partir do banner"""
        banner_lower = banner.lower()
        
        if 'ubuntu' in banner_lower:
            return "Ubuntu Linux"
        elif 'debian' in banner_lower:
            return "Debian Linux"
        elif 'centos' in banner_lower:
            return "CentOS Linux"
        elif 'windows' in banner_lower:
            return "Windows"
        elif 'freebsd' in banner_lower:
            return "FreeBSD"
        
        return None
    
    def _extract_version_from_banner(self, banner: str) -> str:
        """Extrai versão do banner"""
        # Pattern para versões (ex: 2.4.29, 1.10.3, etc.)
        version_pattern = r'(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, banner)
        
        return match.group(1) if match else ""
    
    def _extract_server_type(self, server_header: str) -> str:
        """Extrai tipo de servidor do header"""
        server_lower = server_header.lower()
        
        if 'apache' in server_lower:
            return "Apache"
        elif 'nginx' in server_lower:
            return "Nginx"
        elif 'iis' in server_lower:
            return "IIS"
        elif 'tomcat' in server_lower:
            return "Tomcat"
        
        return server_header.split('/')[0] if '/' in server_header else server_header
    
    def _detect_programming_language(self, powered_by: str) -> str:
        """Detecta linguagem de programação"""
        powered_by_lower = powered_by.lower()
        
        if 'php' in powered_by_lower:
            return "PHP"
        elif 'asp.net' in powered_by_lower:
            return "ASP.NET"
        elif 'python' in powered_by_lower:
            return "Python"
        elif 'java' in powered_by_lower:
            return "Java"
        elif 'ruby' in powered_by_lower:
            return "Ruby"
        
        return None
    
    def _categorize_technology(self, tech: str) -> str:
        """Categoriza uma tecnologia"""
        tech_lower = tech.lower()
        
        if tech_lower in ['wordpress', 'drupal', 'joomla', 'magento']:
            return 'cms'
        elif tech_lower in ['apache', 'nginx', 'iis']:
            return 'web_server'
        elif tech_lower in ['laravel', 'symfony', 'django', 'rails']:
            return 'frameworks'
        
        return None
    
    def _analyze_encryption(self, nmap_data: Dict, banner_data: Dict) -> Dict:
        """Analisa status de criptografia"""
        encryption_status = {
            'https_enabled': False,
            'ssl_tls_versions': [],
            'certificate_issues': [],
            'encryption_score': 0
        }
        
        # Verificar HTTPS nas portas web
        if 'web_banners' in banner_data:
            for port in [443, 8443]:
                if port in banner_data['web_banners']:
                    encryption_status['https_enabled'] = True
                    break
        
        # Score de criptografia
        if encryption_status['https_enabled']:
            encryption_status['encryption_score'] = 70
        else:
            encryption_status['encryption_score'] = 20
        
        return encryption_status
    
    def _detect_information_disclosure(self, banner_data: Dict) -> List[str]:
        """Detecta vazamento de informações"""
        disclosures = []
        
        # Verificar banners de rede
        if 'banners' in banner_data:
            for port, banner_info in banner_data['banners'].items():
                banner = banner_info.get('banner', '')
                
                # Procurar informações sensíveis
                if re.search(r'version|server|system|os', banner, re.IGNORECASE):
                    disclosures.append(f"Informações de versão expostas na porta {port}")
        
        # Verificar headers web
        if 'web_banners' in banner_data:
            for port, web_info in banner_data['web_banners'].items():
                headers = web_info.get('headers', {})
                
                sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                for header in sensitive_headers:
                    if header in headers:
                        disclosures.append(f"Header sensível exposto na porta {port}: {header}")
        
        return disclosures
    
    def _calculate_security_score(self, security_posture: Dict) -> int:
        """Calcula score de segurança"""
        score = 100
        
        # Deduzir pontos por problemas
        score -= len(security_posture.get('critical_issues', [])) * 20
        score -= len(security_posture.get('information_disclosure', [])) * 10
        
        # Adicionar pontos por medidas de segurança
        if security_posture.get('security_headers'):
            score += 20
        
        if security_posture.get('encryption_status', {}).get('https_enabled'):
            score += 15
        
        return max(0, min(score, 100))
    
    def _lookup_vulnerabilities(self, software: str, version: str) -> List[str]:
        """Busca vulnerabilidades conhecidas"""
        vulnerabilities = []
        
        software_clean = software.lower().strip()
        
        if software_clean in self.known_vulnerabilities:
            software_vulns = self.known_vulnerabilities[software_clean]
            
            if version in software_vulns:
                vulnerabilities.extend(software_vulns[version])
        
        return vulnerabilities
    
    def _identify_critical_services(self, banner_data: Dict) -> List[str]:
        """Identifica serviços críticos"""
        critical_services = []
        
        if 'banners' in banner_data:
            for port, banner_info in banner_data['banners'].items():
                service = banner_info.get('service', '')
                
                if service in ['ssh', 'ftp', 'telnet', 'mysql', 'postgresql']:
                    critical_services.append(f"{service} na porta {port}")
        
        return critical_services
    
    def _detect_outdated_software(self, tech_stack: Dict) -> List[str]:
        """Detecta software desatualizado"""
        outdated = []
        
        # Lista de versões consideradas desatualizadas
        outdated_versions = {
            'Apache': ['2.2', '2.4.29'],
            'Nginx': ['1.10', '1.12'],
            'PHP': ['5.6', '7.0', '7.1'],
            'OpenSSH': ['6.6', '7.4']
        }
        
        for category, items in tech_stack.items():
            for item in items:
                if isinstance(item, dict):
                    software = item.get('type', '')
                    version = item.get('version', '')
                    
                    if software in outdated_versions:
                        for outdated_ver in outdated_versions[software]:
                            if version.startswith(outdated_ver):
                                outdated.append(f"{software} {version}")
        
        return outdated
    
    def _calculate_vulnerability_risk_score(self, vuln_assessment: Dict) -> int:
        """Calcula score de risco de vulnerabilidades"""
        score = 0
        
        # Pontos por vulnerabilidades conhecidas
        score += len(vuln_assessment.get('known_vulnerabilities', [])) * 15
        
        # Pontos por serviços críticos
        score += len(vuln_assessment.get('critical_services', [])) * 10
        
        # Pontos por software desatualizado
        score += len(vuln_assessment.get('outdated_software', [])) * 5
        
        return min(score, 100) 