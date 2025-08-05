#!/usr/bin/env python3
"""
Módulo File Handler
Responsável por manipulação de arquivos de entrada e saída
"""

import json
import csv
import re
from typing import List, Dict
from pathlib import Path
from urllib.parse import urlparse

class FileHandler:
    """Manipulador de arquivos para entrada e saída de dados"""
    
    def __init__(self):
        self.supported_formats = ['.txt', '.csv', '.json']
    
    def load_targets_from_file(self, file_path: str) -> List[str]:
        """Carrega lista de alvos de arquivo"""
        targets = []
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {path_obj}")
        
        try:
            if path_obj.suffix.lower() == '.txt':
                targets = self._load_from_txt(path_obj)
            elif path_obj.suffix.lower() == '.csv':
                targets = self._load_from_csv(path_obj)
            elif path_obj.suffix.lower() == '.json':
                targets = self._load_from_json(path_obj)
            else:
                # Tentar como arquivo de texto simples
                targets = self._load_from_txt(path_obj)
            
            # Limpar e validar alvos
            cleaned_targets = []
            for target in targets:
                cleaned = self._clean_target(target)
                if cleaned and self._validate_target(cleaned):
                    cleaned_targets.append(cleaned)
            
            return cleaned_targets
            
        except Exception as e:
            raise Exception(f"Erro ao carregar arquivo {file_path}: {str(e)}")
    
    def _load_from_txt(self, file_path: Path) -> List[str]:
        """Carrega alvos de arquivo .txt"""
        targets = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignorar comentários
                    targets.append(line)
        
        return targets
    
    def _load_from_csv(self, file_path: Path) -> List[str]:
        """Carrega alvos de arquivo .csv"""
        targets = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            csv_reader = csv.reader(f)
            
            # Pular header se existir
            first_row = next(csv_reader, None)
            if first_row and len(first_row) > 0:
                if not self._validate_target(first_row[0]):
                    pass  # É header, já foi pulado
                else:
                    targets.append(first_row[0])  # Não é header
            
            # Ler resto do arquivo
            for row in csv_reader:
                if row and len(row) > 0:
                    targets.append(row[0])  # Primeira coluna
        
        return targets
    
    def _load_from_json(self, file_path: Path) -> List[str]:
        """Carrega alvos de arquivo .json"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Tentar encontrar campo com targets
            possible_fields = ['targets', 'hosts', 'endpoints', 'urls', 'ips']
            for field in possible_fields:
                if field in data:
                    return data[field]
            
            # Se não encontrou, retornar valores do dict
            return list(data.values())
        
        return []
    
    def _clean_target(self, target: str) -> str:
        """Limpa e normaliza target"""
        if not target:
            return ""
        
        target = target.strip()
        
        # Remover espaços extras
        target = re.sub(r'\s+', '', target)
        
        # Se tem protocolo, extrair apenas host
        if '://' in target:
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
        
        # Remover porta se não for necessária para identificação
        if ':' in target and not self._is_ipv6(target):
            # Manter porta apenas se for não-padrão
            host, port = target.rsplit(':', 1)
            try:
                port_num = int(port)
                if port_num in [80, 443]:  # Portas padrão
                    target = host
            except ValueError:
                pass
        
        return target
    
    def _validate_target(self, target: str) -> bool:
        """Valida se target é válido"""
        if not target:
            return False
        
        # Padrões básicos
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        # Verificar se é IP
        if re.match(ip_pattern, target):
            # Validar ranges do IP
            parts = target.split('.')
            for part in parts:
                if int(part) > 255:
                    return False
            return True
        
        # Verificar se é domínio
        if re.match(domain_pattern, target):
            return True
        
        # Verificar IPv6 básico
        if ':' in target and len(target.split(':')) >= 3:
            return True
        
        return False
    
    def _is_ipv6(self, target: str) -> bool:
        """Verifica se é IPv6"""
        return target.count(':') >= 2
    
    def save_results(self, results: Dict, output_file: str):
        """Salva resultados em arquivo"""
        output_path = Path(output_file)
        
        try:
            if output_path.suffix.lower() == '.json':
                self._save_as_json(results, output_path)
            elif output_path.suffix.lower() == '.csv':
                self._save_as_csv(results, output_path)
            elif output_path.suffix.lower() == '.html':
                self._save_as_html(results, output_path)
            else:
                # Default: JSON
                self._save_as_json(results, output_path.with_suffix('.json'))
                
        except Exception as e:
            raise Exception(f"Erro ao salvar arquivo {output_file}: {str(e)}")
    
    def _save_as_json(self, results: Dict, file_path: Path):
        """Salva resultados como JSON"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    def _save_as_csv(self, results: Dict, file_path: Path):
        """Salva resultados como CSV"""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Target', 'Risk Level', 'Open Ports', 'Exposed Services',
                'Technology Stack', 'Vulnerabilities', 'Timestamp'
            ])
            
            # Dados
            for target_data in results.get('targets', []):
                target = target_data.get('target', '')
                risk_level = target_data.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
                
                # Portas abertas
                open_ports = target_data.get('nmap_scan', {}).get('open_ports', [])
                ports_str = ','.join(map(str, open_ports))
                
                # Serviços expostos
                exposed_services = target_data.get('banners', {}).get('exposed_services', [])
                services_str = '; '.join(exposed_services[:3])  # Limitar para legibilidade
                
                # Stack tecnológico
                tech_stack = target_data.get('footprint', {}).get('technology_stack', {})
                tech_items = []
                for category, items in tech_stack.items():
                    if isinstance(items, list) and items:
                        tech_items.extend(items[:2])  # Limitar quantidade
                tech_str = ', '.join(tech_items[:5])
                
                # Vulnerabilidades
                vulns = target_data.get('footprint', {}).get('vulnerability_assessment', {}).get('known_vulnerabilities', [])
                vulns_str = ', '.join(vulns[:3])
                
                timestamp = target_data.get('timestamp', '')
                
                writer.writerow([
                    target, risk_level, ports_str, services_str,
                    tech_str, vulns_str, timestamp
                ])
    
    def _save_as_html(self, results: Dict, file_path: Path):
        """Salva resultados como HTML"""
        html_content = self._generate_html_report(results)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_html_report(self, results: Dict) -> str:
        """Gera relatório HTML"""
        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Banner Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; text-align: center; }}
        h2 {{ color: #444; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        h3 {{ color: #555; margin-top: 20px; }}
        .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .target {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 15px; }}
        .risk-high {{ border-left: 5px solid #dc3545; }}
        .risk-medium {{ border-left: 5px solid #ffc107; }}
        .risk-low {{ border-left: 5px solid #28a745; }}
        .risk-info {{ border-left: 5px solid #17a2b8; }}
        .metasploit-section {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .exploit-item {{ background: #fff; border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .exploit-high {{ border-left: 4px solid #dc3545; }}
        .exploit-medium {{ border-left: 4px solid #ffc107; }}
        .exploit-low {{ border-left: 4px solid #28a745; }}
        .auxiliary-item {{ background: #e7f3ff; border: 1px solid #b3d9ff; padding: 8px; margin: 3px 0; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-high {{ background-color: #dc3545; color: white; }}
        .badge-medium {{ background-color: #ffc107; color: black; }}
        .badge-low {{ background-color: #28a745; color: white; }}
        .badge-info {{ background-color: #17a2b8; color: white; }}
        .badge-critical {{ background-color: #721c24; color: white; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #333; }}
        .stat-label {{ color: #666; font-size: 14px; }}
        .warning-box {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .success-box {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Banner Scanner & Footprinting Report</h1>
        
        <div class="summary">
            <h2>📊 Resumo Executivo</h2>
            <p><strong>Total de Alvos:</strong> {results.get('summary', {}).get('total_targets', 0)}</p>
            <p><strong>Alvos de Alto Risco:</strong> {results.get('summary', {}).get('high_risk_targets', 0)}</p>
            <p><strong>Gerado em:</strong> {results.get('scan_info', {}).get('timestamp', 'N/A')}</p>
        </div>
"""
        
        # Adicionar detalhes de cada alvo
        for target_data in results.get('targets', []):
            target = target_data.get('target', '')
            risk_level = target_data.get('risk_assessment', {}).get('risk_level', 'INFO')
            risk_class = f"risk-{risk_level.lower()}"
            
            html += f"""
        <div class="target {risk_class}">
            <h2>🎯 {target} <span class="badge badge-{risk_level.lower()}">{risk_level}</span></h2>
"""
            
            # Portas abertas
            open_ports = target_data.get('nmap_scan', {}).get('open_ports', [])
            if open_ports:
                html += f"<p><strong>🔌 Portas Abertas:</strong> {', '.join(map(str, open_ports))}</p>"
            
            # Serviços expostos
            exposed_services = target_data.get('banners', {}).get('exposed_services', [])
            if exposed_services:
                html += "<p><strong>🌐 Serviços Expostos:</strong></p><ul>"
                for service in exposed_services[:10]:  # Limitar para legibilidade
                    html += f"<li>{service}</li>"
                html += "</ul>"
            
            # Seção Metasploit
            metasploit_data = target_data.get('metasploit_scan', {})
            if metasploit_data:
                html += self._generate_metasploit_html_section(metasploit_data)
            
            # Vulnerabilidades
            vulns = target_data.get('footprint', {}).get('vulnerability_assessment', {}).get('known_vulnerabilities', [])
            if vulns:
                html += "<p><strong>🚨 Vulnerabilidades Conhecidas:</strong></p><ul>"
                for vuln in vulns[:10]:
                    html += f"<li>{vuln}</li>"
                html += "</ul>"
            
            html += "</div>"
        
        html += """
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_metasploit_html_section(self, metasploit_data: Dict) -> str:
        """Gera seção HTML para resultados do Metasploit"""
        html = """
        <div class="metasploit-section">
            <h3>🛡️ Análise Metasploit</h3>
"""
        
        # Estatísticas do scan
        scan_summary = metasploit_data.get('scan_summary', {})
        if scan_summary:
            html += """
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{}</div>
                    <div class="stat-label">Portas Analisadas</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{}</div>
                    <div class="stat-label">Exploits Encontrados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{}</div>
                    <div class="stat-label">Módulos Auxiliares</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{}</div>
                    <div class="stat-label">Vulnerabilidades Confirmadas</div>
                </div>
            </div>
""".format(
                scan_summary.get('ports_scanned', 0),
                scan_summary.get('exploits_found', 0),
                scan_summary.get('auxiliary_modules_executed', 0),
                scan_summary.get('confirmed_vulnerabilities', 0)
            )
        
        # Exploits encontrados
        exploits_found = metasploit_data.get('exploits_found', [])
        if exploits_found:
            html += "<h4>🎯 Exploits Identificados</h4>"
            for exploit in exploits_found[:10]:  # Limitar para performance
                severity = exploit.get('severity', 'medium').lower()
                cve = exploit.get('cve', 'N/A')
                description = exploit.get('description', 'Sem descrição')
                service = exploit.get('service', 'N/A')
                
                html += f"""
                <div class="exploit-item exploit-{severity}">
                    <strong>{exploit.get('name', 'Exploit Desconhecido')}</strong>
                    <span class="badge badge-{severity}">{severity.upper()}</span>
                    <br><small><strong>CVE:</strong> {cve} | <strong>Serviço:</strong> {service}</small>
                    <br><small>{description[:150]}{'...' if len(description) > 150 else ''}</small>
                </div>
"""
        
        # Vulnerabilidades confirmadas
        confirmed_vulns = metasploit_data.get('confirmed_vulnerabilities', [])
        if confirmed_vulns:
            html += "<h4>⚠️ Vulnerabilidades Confirmadas</h4>"
            for vuln in confirmed_vulns[:5]:  # Limitar para performance
                severity = vuln.get('severity', 'medium').lower()
                cve = vuln.get('cve', 'N/A')
                impact = vuln.get('impact', 'Impacto não especificado')
                
                html += f"""
                <div class="warning-box">
                    <strong>🚨 {vuln.get('name', 'Vulnerabilidade Confirmada')}</strong>
                    <span class="badge badge-{severity}">{severity.upper()}</span>
                    <br><small><strong>CVE:</strong> {cve}</small>
                    <br><small><strong>Impacto:</strong> {impact}</small>
                </div>
"""
        
        # Resultados auxiliares
        auxiliary_results = metasploit_data.get('auxiliary_results', [])
        if auxiliary_results:
            html += "<h4>🔍 Resultados de Módulos Auxiliares</h4>"
            for aux in auxiliary_results[:8]:  # Limitar para performance
                module_name = aux.get('module', 'Módulo Desconhecido')
                result = aux.get('result', 'Sem resultado')
                
                html += f"""
                <div class="auxiliary-item">
                    <strong>{module_name}</strong>
                    <br><small>{result[:100]}{'...' if len(result) > 100 else ''}</small>
                </div>
"""
        
        # Avisos de segurança
        security_warnings = metasploit_data.get('security_warnings', [])
        if security_warnings:
            html += "<h4>⚠️ Avisos de Segurança</h4>"
            for warning in security_warnings[:5]:
                html += f"""
                <div class="warning-box">
                    <strong>⚠️ {warning}</strong>
                </div>
"""
        
        # Se não há dados do Metasploit
        if not any([exploits_found, confirmed_vulns, auxiliary_results, security_warnings]):
            html += """
            <div class="success-box">
                <strong>✅ Nenhum exploit ou vulnerabilidade crítica detectada pelo Metasploit</strong>
                <br><small>O scan não identificou vulnerabilidades exploráveis conhecidas neste alvo.</small>
            </div>
"""
        
        html += "</div>"  # Fechar metasploit-section
        return html