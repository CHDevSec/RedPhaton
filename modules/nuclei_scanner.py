#!/usr/bin/env python3
"""
Módulo Nuclei Scanner
Responsável por execução de scans Nuclei para detecção de vulnerabilidades
"""

import subprocess
import json
import os
import tempfile
from typing import Dict, List, Optional
from pathlib import Path

class NucleiScanner:
    """Scanner Nuclei para detecção automatizada de vulnerabilidades"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.nuclei_path = self._find_nuclei_binary()
        self.templates_path = self._get_templates_path()
        
    def _find_nuclei_binary(self) -> Optional[str]:
        """Localiza o binário do Nuclei no sistema"""
        possible_paths = [
            'nuclei',
            'nuclei.exe',
            '/usr/local/bin/nuclei',
            '/usr/bin/nuclei',
            os.path.expanduser('~/go/bin/nuclei')
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '-version'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    if self.logger:
                        self.logger.info(f"Nuclei encontrado em: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        if self.logger:
            self.logger.warning("Nuclei não encontrado no sistema")
        return None
    
    def _get_templates_path(self) -> Optional[str]:
        """Obtém o caminho dos templates do Nuclei"""
        if not self.nuclei_path:
            return None
            
        # Tentar localizar templates
        possible_template_paths = [
            os.path.expanduser('~/nuclei-templates'),
            '/usr/share/nuclei-templates',
            './nuclei-templates'
        ]
        
        for path in possible_template_paths:
            if os.path.exists(path):
                return path
                
        return None
    
    def scan_target(self, target: str, scan_type: str = 'comprehensive') -> Dict:
        """Executa scan Nuclei no alvo especificado"""
        results = {
            'target': target,
            'scan_type': scan_type,
            'vulnerabilities': [],
            'info_disclosures': [],
            'misconfigurations': [],
            'exposed_panels': [],
            'technologies': [],
            'total_findings': 0,
            'severity_stats': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'scan_status': 'failed'
        }
        
        if not self.nuclei_path:
            if self.logger:
                self.logger.error("Nuclei não está instalado ou não foi encontrado")
            results['error'] = "Nuclei não encontrado"
            return results
        
        try:
            # Executar diferentes tipos de scan baseado no parâmetro
            if scan_type == 'quick':
                scan_results = self._run_quick_scan(target)
            elif scan_type == 'comprehensive':
                scan_results = self._run_comprehensive_scan(target)
            elif scan_type == 'critical':
                scan_results = self._run_critical_scan(target)
            elif scan_type == 'aggressive':
                scan_results = self._run_aggressive_scan(target)
            elif scan_type == 'redteam':
                scan_results = self._run_redteam_scan(target)
            elif scan_type == 'bugbounty':
                scan_results = self._run_bugbounty_scan(target)
            else:
                scan_results = self._run_comprehensive_scan(target)
            
            # Processar resultados
            results = self._parse_nuclei_results(scan_results, results)
            results['scan_status'] = 'completed'
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro no scan Nuclei de {target}: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def _run_quick_scan(self, target: str) -> str:
        """Executa scan rápido focado em vulnerabilidades críticas"""
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-severity', 'critical,high,medium',
            '-tags', 'cve,rce,sqli,xss,lfi,rfi,ssrf,xxe,ssti,deserialization',
            '-json',
            '-silent',
            '-timeout', '15',
            '-retries', '2',
            '-rate-limit', '100',
            '-bulk-size', '25',
            '-c', '25'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        return self._execute_nuclei_command(cmd)
    
    def _run_comprehensive_scan(self, target: str) -> str:
        """Executa scan completo com todos os templates"""
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-tags', 'cve,rce,sqli,xss,lfi,rfi,ssrf,xxe,ssti,deserialization,exposure,misconfiguration,takeover,injection,bypass,disclosure',
            '-severity', 'critical,high,medium,low',
            '-json',
            '-silent',
            '-timeout', '20',
            '-retries', '3',
            '-rate-limit', '200',
            '-bulk-size', '50',
            '-c', '50',
            '-follow-redirects',
            '-max-redirects', '3'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        return self._execute_nuclei_command(cmd)
    
    def _run_critical_scan(self, target: str) -> str:
        """Executa scan focado apenas em vulnerabilidades críticas"""
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-severity', 'critical,high',
            '-tags', 'cve,rce,sqli,deserialization,bypass,takeover,exposure',
            '-json',
            '-silent',
            '-timeout', '25',
            '-retries', '4',
            '-rate-limit', '150',
            '-bulk-size', '30',
            '-c', '30',
            '-follow-redirects'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        return self._execute_nuclei_command(cmd)
    
    def _run_aggressive_scan(self, target: str) -> str:
        """Executa scan agressivo com alta concorrência e timeout estendido"""
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-tags', 'cve,rce,sqli,xss,lfi,rfi,ssrf,xxe,ssti,deserialization,exposure,misconfiguration,takeover,injection,bypass,disclosure,fuzzing',
            '-severity', 'critical,high,medium,low,info',
            '-jsonl',
            '-silent',
            '-timeout', '30',
            '-retries', '5',
            '-rate-limit', '500',
            '-bulk-size', '100',
            '-c', '100',
            '-follow-redirects',
            '-max-redirects', '5',
            '-include-rr',
            '-disable-clustering'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        return self._execute_nuclei_command(cmd)
    
    def _run_redteam_scan(self, target: str) -> str:
        """Executa scan focado em técnicas de Red Team"""
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-tags', 'rce,sqli,deserialization,bypass,takeover,exposure,disclosure,default-login,weak-auth,file-upload,directory-traversal,command-injection',
            '-severity', 'critical,high,medium',
            '-json',
            '-silent',
            '-timeout', '35',
            '-retries', '6',
            '-rate-limit', '300',
            '-bulk-size', '75',
            '-c', '75',
            '-follow-redirects',
            '-max-redirects', '10',
            '-include-rr',
            '-disable-clustering',
            '-attack-type', 'batteringram'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        return self._execute_nuclei_command(cmd)
    
    def _run_bugbounty_scan(self, target: str) -> str:
        """Executa scan otimizado para bug bounty hunting"""
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-tags', 'cve,xss,sqli,ssrf,lfi,rfi,xxe,ssti,open-redirect,cors,csrf,idor,prototype-pollution,subdomain-takeover,dns-rebinding',
            '-severity', 'critical,high,medium,low',
            '-json',
            '-silent',
            '-timeout', '25',
            '-retries', '4',
            '-rate-limit', '400',
            '-bulk-size', '80',
            '-c', '80',
            '-follow-redirects',
            '-max-redirects', '7',
            '-include-rr',
            '-passive',
            '-headless'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        return self._execute_nuclei_command(cmd)
    
    def scan_with_custom_templates(self, target: str, template_tags: List[str]) -> Dict:
        """Executa scan com templates específicos baseados em tags"""
        if not self.nuclei_path:
            return {'error': 'Nuclei não encontrado'}
        
        cmd = [
            self.nuclei_path,
            '-target', target,
            '-tags', ','.join(template_tags),
            '-json',
            '-silent'
        ]
        
        if self.templates_path:
            cmd.extend(['-t', self.templates_path])
        
        try:
            output = self._execute_nuclei_command(cmd)
            results = {
                'target': target,
                'template_tags': template_tags,
                'vulnerabilities': [],
                'scan_status': 'completed'
            }
            return self._parse_nuclei_results(output, results)
        except Exception as e:
            return {'error': str(e), 'scan_status': 'failed'}
    
    def _execute_nuclei_command(self, cmd: List[str]) -> str:
        """Executa comando Nuclei e retorna output"""
        if self.logger:
            self.logger.info(f"Executando: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutos timeout
                cwd=os.getcwd()
            )
            
            if result.returncode != 0 and result.stderr:
                if self.logger:
                    self.logger.warning(f"Nuclei stderr: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise Exception("Timeout no scan Nuclei")
        except Exception as e:
            raise Exception(f"Erro ao executar Nuclei: {str(e)}")
    
    def _parse_nuclei_results(self, output: str, results: Dict) -> Dict:
        """Processa output JSON do Nuclei"""
        if not output.strip():
            return results
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                finding = json.loads(line)
                processed_finding = self._process_finding(finding)
                
                # Categorizar finding
                severity = processed_finding.get('severity', 'info').lower()
                category = processed_finding.get('category', 'other')
                
                if category == 'vulnerability':
                    results['vulnerabilities'].append(processed_finding)
                elif category == 'exposure':
                    results['info_disclosures'].append(processed_finding)
                elif category == 'misconfiguration':
                    results['misconfigurations'].append(processed_finding)
                elif category == 'panel':
                    results['exposed_panels'].append(processed_finding)
                elif category == 'technology':
                    results['technologies'].append(processed_finding)
                
                # Atualizar estatísticas de severidade
                if severity in results['severity_stats']:
                    results['severity_stats'][severity] += 1
                
                results['total_findings'] += 1
                
            except json.JSONDecodeError:
                if self.logger:
                    self.logger.warning(f"Erro ao parsear linha JSON: {line}")
                continue
        
        return results
    
    def _process_finding(self, finding: Dict) -> Dict:
        """Processa um finding individual do Nuclei"""
        processed = {
            'template_id': finding.get('template-id', 'unknown'),
            'name': finding.get('info', {}).get('name', 'Unknown'),
            'severity': finding.get('info', {}).get('severity', 'info'),
            'description': finding.get('info', {}).get('description', ''),
            'reference': finding.get('info', {}).get('reference', []),
            'tags': finding.get('info', {}).get('tags', []),
            'matched_at': finding.get('matched-at', ''),
            'extracted_results': finding.get('extracted-results', []),
            'curl_command': finding.get('curl-command', ''),
            'timestamp': finding.get('timestamp', ''),
            'category': self._categorize_finding(finding)
        }
        
        # Adicionar informações de CVE se disponível
        classification = finding.get('info', {}).get('classification', {})
        if 'cve-id' in classification:
            processed['cve_id'] = classification['cve-id']
        if 'cwe-id' in classification:
            processed['cwe_id'] = classification['cwe-id']
        
        return processed
    
    def _categorize_finding(self, finding: Dict) -> str:
        """Categoriza o finding baseado em tags e informações"""
        tags = finding.get('info', {}).get('tags', [])
        template_id = finding.get('template-id', '').lower()
        
        # Categorização baseada em tags
        if any(tag in ['cve', 'vulnerability', 'rce', 'sqli', 'xss'] for tag in tags):
            return 'vulnerability'
        elif any(tag in ['exposure', 'disclosure', 'config'] for tag in tags):
            return 'exposure'
        elif any(tag in ['panel', 'login', 'admin'] for tag in tags):
            return 'panel'
        elif any(tag in ['tech', 'detect', 'fingerprint'] for tag in tags):
            return 'technology'
        elif any(tag in ['misconfig', 'default'] for tag in tags):
            return 'misconfiguration'
        
        # Categorização baseada no template ID
        if any(keyword in template_id for keyword in ['cve-', 'vuln-', 'rce-']):
            return 'vulnerability'
        elif any(keyword in template_id for keyword in ['panel-', 'login-', 'admin-']):
            return 'panel'
        elif any(keyword in template_id for keyword in ['tech-', 'detect-']):
            return 'technology'
        
        return 'other'
    
    def update_templates(self) -> bool:
        """Atualiza templates do Nuclei"""
        if not self.nuclei_path:
            return False
        
        try:
            cmd = [self.nuclei_path, '-update-templates']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                if self.logger:
                    self.logger.info("Templates do Nuclei atualizados com sucesso")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Erro ao atualizar templates: {result.stderr}")
                return False
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro ao atualizar templates: {str(e)}")
            return False
    
    def get_template_stats(self) -> Dict:
        """Obtém estatísticas dos templates disponíveis"""
        if not self.nuclei_path:
            return {'error': 'Nuclei não encontrado'}
        
        try:
            cmd = [self.nuclei_path, '-tl']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Contar templates por categoria
                lines = result.stdout.split('\n')
                stats = {
                    'total_templates': len([l for l in lines if l.strip()]),
                    'categories': {}
                }
                return stats
            else:
                return {'error': 'Erro ao obter estatísticas'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def is_available(self) -> bool:
        """Verifica se o Nuclei está disponível no sistema"""
        return self.nuclei_path is not None
    
    def get_version(self) -> str:
        """Obtém versão do Nuclei instalado"""
        if not self.nuclei_path:
            return "Não instalado"
        
        try:
            result = subprocess.run([self.nuclei_path, '-version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
            return "Versão desconhecida"
        except:
            return "Erro ao obter versão"