#!/usr/bin/env python3
"""
Módulo Nmap Scanner
Responsável por execução de scans Nmap para descoberta de portas e serviços
"""

import subprocess
import json
import re
from typing import Dict, List, Optional

class NmapScanner:
    """Scanner Nmap para descoberta de portas e identificação de serviços"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.default_ports = "22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"
    
    def scan_target(self, target: str) -> Dict:
        """Executa scan Nmap completo no alvo"""
        results = {
            'target': target,
            'open_ports': [],
            'services': {},
            'os_detection': {},
            'vulnerabilities': [],
            'raw_output': ''
        }
        
        try:
            # 1. Scan básico de portas
            basic_scan = self._run_basic_scan(target)
            results.update(basic_scan)
            
            # 2. Scan de versões nos serviços encontrados
            if results['open_ports']:
                version_scan = self._run_version_scan(target, results['open_ports'])
                results['services'].update(version_scan)
            
            # 3. Detecção de OS
            os_scan = self._run_os_detection(target)
            results['os_detection'] = os_scan
            
            # 4. Scan de vulnerabilidades básicas
            vuln_scan = self._run_vuln_scan(target)
            results['vulnerabilities'] = vuln_scan
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro no scan Nmap de {target}: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _run_basic_scan(self, target: str) -> Dict:
        """Executa scan básico de portas"""
        cmd = [
            'nmap', '-sS', '-T4', '-p', self.default_ports,
            '--max-retries', '2', '--max-rtt-timeout', '2s',
            target
        ]
        
        if self.logger:
            self.logger.debug(f"Executando: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'open_ports': self._parse_open_ports(result.stdout),
                'raw_output': result.stdout
            }
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.warning(f"Timeout no scan básico de {target}")
            return {'open_ports': [], 'raw_output': 'Timeout'}
    
    def _run_version_scan(self, target: str, ports: List[int]) -> Dict:
        """Executa scan de versões dos serviços"""
        if not ports:
            return {}
        
        port_list = ','.join(map(str, ports))
        cmd = [
            'nmap', '-sV', '-p', port_list,
            '--version-intensity', '5',
            target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            return self._parse_service_versions(result.stdout)
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.warning(f"Timeout no scan de versões de {target}")
            return {}
    
    def _run_os_detection(self, target: str) -> Dict:
        """Executa detecção de Sistema Operacional"""
        cmd = ['nmap', '-O', '--osscan-guess', target]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            return self._parse_os_detection(result.stdout)
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.warning(f"Timeout na detecção de OS de {target}")
            return {}
    
    def _run_vuln_scan(self, target: str) -> List[str]:
        """Executa scan básico de vulnerabilidades"""
        cmd = ['nmap', '--script', 'vuln', '--script-args', 'unsafe=1', target]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return self._parse_vulnerabilities(result.stdout)
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.warning(f"Timeout no scan de vulnerabilidades de {target}")
            return []
    
    def _parse_open_ports(self, nmap_output: str) -> List[int]:
        """Extrai portas abertas do output do Nmap"""
        ports = []
        port_pattern = r'(\d+)/tcp\s+open'
        
        for match in re.finditer(port_pattern, nmap_output):
            ports.append(int(match.group(1)))
        
        return sorted(ports)
    
    def _parse_service_versions(self, nmap_output: str) -> Dict:
        """Extrai informações de versões dos serviços"""
        services = {}
        # Pattern para capturar serviços e versões
        service_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s+([^\n]+)'
        for match in re.finditer(service_pattern, nmap_output):
            port = int(match.group(1))
            service = match.group(2)
            version_info = match.group(3).strip()
            services[port] = {
                'service': service,
                'version': version_info,
                'potential_banner': self._extract_banner_info(version_info)
            }
        return services
    
    def _parse_os_detection(self, nmap_output: str) -> Dict:
        """Extrai informações de detecção de OS"""
        os_info = {
            'detected_os': [],
            'accuracy': 0,
            'fingerprint': ''
        }
        
        # Pattern para OS detection
        os_pattern = r'Running:\s*([^\n]+)'
        accuracy_pattern = r'Aggressive OS guesses:\s*([^\n]+)\s*\((\d+)%\)'
        
        os_match = re.search(os_pattern, nmap_output)
        if os_match:
            os_info['detected_os'].append(os_match.group(1).strip())
        
        accuracy_match = re.search(accuracy_pattern, nmap_output)
        if accuracy_match:
            os_info['detected_os'].append(accuracy_match.group(1).strip())
            os_info['accuracy'] = int(accuracy_match.group(2))
        
        return os_info
    
    def _parse_vulnerabilities(self, nmap_output: str) -> List[str]:
        """Extrai vulnerabilidades encontradas"""
        vulnerabilities = []
        
        # Patterns para vulnerabilidades comuns
        vuln_patterns = [
            r'(\|.*CVE-\d+-\d+.*)',
            r'(\|.*VULNERABLE.*)',
            r'(\|.*HIGH.*)',
            r'(\|.*CRITICAL.*)'
        ]
        
        for pattern in vuln_patterns:
            matches = re.findall(pattern, nmap_output, re.IGNORECASE)
            vulnerabilities.extend([match.strip() for match in matches])
        
        return list(set(vulnerabilities))  # Remove duplicatas
    
    def _extract_banner_info(self, version_info: str) -> str:
        """Extrai informações de banner das versões"""
        # Remove informações desnecessárias e mantém só o essencial
        banner_info = version_info
        
        # Patterns para limpar
        cleanup_patterns = [
            r'\([^)]*\)',  # Remove conteúdo entre parênteses
            r'[\r\n\t]+',  # Remove quebras de linha e tabs
        ]
        
        for pattern in cleanup_patterns:
            banner_info = re.sub(pattern, ' ', banner_info)
        
        return banner_info.strip() 