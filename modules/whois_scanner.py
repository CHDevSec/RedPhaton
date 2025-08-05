#!/usr/bin/env python3
"""
Módulo Whois Scanner
Responsável por coleta de informações WHOIS e análise de domínios
"""

import subprocess
import re
import socket
from typing import Dict, List
from urllib.parse import urlparse

class WhoisScanner:
    """Scanner WHOIS para coleta de informações de domínio e infraestrutura"""
    
    def __init__(self, logger=None):
        self.logger = logger
    
    def lookup_target(self, target: str) -> Dict:
        """Executa lookup WHOIS completo no alvo"""
        results = {
            'target': target,
            'is_ip': self._is_ip_address(target),
            'domain_info': {},
            'ip_info': {},
            'dns_records': {},
            'registrar_info': {},
            'raw_whois': ''
        }
        
        try:
            # Limpar target (remover protocolo se houver)
            clean_target = self._clean_target(target)
            
            if results['is_ip']:
                # Lookup para IP
                ip_whois = self._whois_ip_lookup(clean_target)
                results['ip_info'] = ip_whois
            else:
                # Lookup para domínio
                domain_whois = self._whois_domain_lookup(clean_target)
                results['domain_info'] = domain_whois
                
                # Resolver IP do domínio
                resolved_ip = self._resolve_domain(clean_target)
                if resolved_ip:
                    results['ip_info'] = self._whois_ip_lookup(resolved_ip)
            
            # DNS Records
            results['dns_records'] = self._get_dns_records(clean_target)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro no WHOIS lookup de {target}: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _clean_target(self, target: str) -> str:
        """Limpa o target removendo protocolo e paths"""
        # Remove protocolo
        if '://' in target:
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
        
        # Remove porta
        if ':' in target and not self._is_ipv6(target):
            target = target.split(':')[0]
        
        # Remove path
        if '/' in target:
            target = target.split('/')[0]
        
        return target.strip()
    
    def _is_ip_address(self, target: str) -> bool:
        """Verifica se o target é um endereço IP"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, target)
                return True
            except socket.error:
                return False
    
    def _is_ipv6(self, target: str) -> bool:
        """Verifica se é IPv6"""
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except socket.error:
            return False
    
    def _whois_domain_lookup(self, domain: str) -> Dict:
        """Executa WHOIS lookup para domínio"""
        try:
            result = subprocess.run(['whois', domain], 
                                  capture_output=True, text=True, timeout=30)
            
            whois_data = result.stdout
            
            return {
                'registrar': self._extract_registrar(whois_data),
                'creation_date': self._extract_creation_date(whois_data),
                'expiration_date': self._extract_expiration_date(whois_data),
                'nameservers': self._extract_nameservers(whois_data),
                'status': self._extract_domain_status(whois_data),
                'contacts': self._extract_contacts(whois_data),
                'raw_whois': whois_data
            }
            
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.warning(f"Timeout no WHOIS lookup de {domain}")
            return {'error': 'Timeout'}
        except Exception as e:
            return {'error': str(e)}
    
    def _whois_ip_lookup(self, ip: str) -> Dict:
        """Executa WHOIS lookup para IP"""
        try:
            result = subprocess.run(['whois', ip], 
                                  capture_output=True, text=True, timeout=30)
            
            whois_data = result.stdout
            
            return {
                'network': self._extract_network_info(whois_data),
                'organization': self._extract_organization(whois_data),
                'country': self._extract_country(whois_data),
                'abuse_contact': self._extract_abuse_contact(whois_data),
                'asn': self._extract_asn(whois_data),
                'raw_whois': whois_data
            }
            
        except subprocess.TimeoutExpired:
            if self.logger:
                self.logger.warning(f"Timeout no WHOIS lookup de {ip}")
            return {'error': 'Timeout'}
        except Exception as e:
            return {'error': str(e)}
    
    def _resolve_domain(self, domain: str) -> str:
        """Resolve domínio para IP"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
    
    def _get_dns_records(self, target: str) -> Dict:
        """Coleta registros DNS básicos"""
        dns_info = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': []
        }
        
        try:
            # Usar dig se disponível, senão nslookup
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                records = self._query_dns_record(target, record_type)
                dns_info[f'{record_type.lower()}_records'] = records
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro na consulta DNS de {target}: {str(e)}")
            dns_info['error'] = str(e)
        
        return dns_info
    
    def _query_dns_record(self, target: str, record_type: str) -> List[str]:
        """Consulta um tipo específico de registro DNS"""
        try:
            # Tentar dig primeiro
            result = subprocess.run(['dig', '+short', record_type, target],
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                return [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            
            # Fallback para nslookup
            result = subprocess.run(['nslookup', '-type=' + record_type, target],
                                  capture_output=True, text=True, timeout=15)
            
            return self._parse_nslookup_output(result.stdout, record_type)
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
    
    def _parse_nslookup_output(self, output: str, record_type: str) -> List[str]:
        """Parse do output do nslookup"""
        records = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if record_type == 'A' and 'Address:' in line and not 'server' in line.lower():
                records.append(line.split('Address:')[1].strip())
            elif record_type == 'MX' and 'mail exchanger' in line:
                records.append(line.split('=')[1].strip())
            elif record_type == 'NS' and 'nameserver' in line:
                records.append(line.split('=')[1].strip())
            elif record_type == 'TXT' and 'text' in line:
                records.append(line.split('=')[1].strip())
        
        return records
    
    # Métodos para extrair informações específicas do WHOIS
    def _extract_registrar(self, whois_data: str) -> str:
        patterns = [r'Registrar:\s*(.+)', r'Registrar Name:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_creation_date(self, whois_data: str) -> str:
        patterns = [r'Creation Date:\s*(.+)', r'Created:\s*(.+)', r'Registered:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_expiration_date(self, whois_data: str) -> str:
        patterns = [r'Expiration Date:\s*(.+)', r'Expires:\s*(.+)', r'Expiry Date:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_nameservers(self, whois_data: str) -> List[str]:
        nameservers = []
        patterns = [r'Name Server:\s*(.+)', r'Nameserver:\s*(.+)']
        
        for pattern in patterns:
            matches = re.findall(pattern, whois_data, re.IGNORECASE)
            nameservers.extend([ns.strip() for ns in matches])
        
        return list(set(nameservers))
    
    def _extract_domain_status(self, whois_data: str) -> List[str]:
        patterns = [r'Status:\s*(.+)', r'Domain Status:\s*(.+)']
        statuses = []
        
        for pattern in patterns:
            matches = re.findall(pattern, whois_data, re.IGNORECASE)
            statuses.extend([status.strip() for status in matches])
        
        return list(set(statuses))
    
    def _extract_contacts(self, whois_data: str) -> Dict:
        return {
            'admin_email': self._extract_with_patterns(whois_data, [r'Admin Email:\s*(.+)']),
            'tech_email': self._extract_with_patterns(whois_data, [r'Tech Email:\s*(.+)']),
            'billing_email': self._extract_with_patterns(whois_data, [r'Billing Email:\s*(.+)'])
        }
    
    def _extract_network_info(self, whois_data: str) -> str:
        patterns = [r'NetRange:\s*(.+)', r'inetnum:\s*(.+)', r'Network:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_organization(self, whois_data: str) -> str:
        patterns = [r'Organization:\s*(.+)', r'OrgName:\s*(.+)', r'org:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_country(self, whois_data: str) -> str:
        patterns = [r'Country:\s*(.+)', r'country:\s*(.+)', r'Country Code:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_abuse_contact(self, whois_data: str) -> str:
        patterns = [r'abuse-mailbox:\s*(.+)', r'Abuse Contact:\s*(.+)', r'OrgAbuseEmail:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_asn(self, whois_data: str) -> str:
        patterns = [r'ASN:\s*(.+)', r'OriginAS:\s*(.+)', r'origin:\s*(.+)']
        return self._extract_with_patterns(whois_data, patterns)
    
    def _extract_with_patterns(self, text: str, patterns: List[str]) -> str:
        """Extrai informação usando múltiplos patterns"""
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "" 