#!/usr/bin/env python3
"""
Módulo Output Formatter
Responsável por formatação e exibição de resultados na tela
"""

import json
from typing import Dict, List
from datetime import datetime

class OutputFormatter:
    """Formatador de saída para exibição de resultados"""
    
    def __init__(self):
        # Cores para output
        self.colors = {
            'CRITICAL': '\033[95m',  # Magenta
            'HIGH': '\033[91m',      # Vermelho
            'MEDIUM': '\033[93m',    # Amarelo
            'LOW': '\033[92m',       # Verde
            'INFO': '\033[94m',      # Azul
            'RESET': '\033[0m',      # Reset
            'BOLD': '\033[1m',       # Negrito
            'UNDERLINE': '\033[4m'   # Sublinhado
        }
    
    def display_summary(self, results: Dict):
        """Exibe resumo dos resultados na tela"""
        print("\n" + "="*80)
        print(f"{self.colors['BOLD']}BANNER SCANNER & FOOTPRINTING REPORT{self.colors['RESET']}")
        print("="*80)
        
        # Informações gerais
        scan_info = results.get('scan_info', {})
        summary = results.get('summary', {})
        
        print(f"\n{self.colors['BOLD']}📊 RESUMO GERAL{self.colors['RESET']}")
        print(f"  Timestamp: {scan_info.get('timestamp', 'N/A')}")
        print(f"  Modo: {scan_info.get('mode', 'N/A').upper()}")
        print(f"  Total de Alvos: {summary.get('total_targets', 0)}")
        print(f"  Alvos de Alto Risco: {summary.get('high_risk_targets', 0)}")
        if 'scan_duration' in summary:
            print(f"  Tempo total do scan: {summary['scan_duration']:.2f} segundos")
        
        # Estatísticas por nível de risco
        self._display_risk_statistics(results)
        
        # Detalhes de cada alvo
        print(f"\n{self.colors['BOLD']}🎯 DETALHES DOS ALVOS{self.colors['RESET']}")
        print("-"*60)
        
        targets = results.get('targets', [])
        for i, target_data in enumerate(targets, 1):
            self._display_target_summary(target_data, i, len(targets))
        
        # Recomendações gerais
        self._display_general_recommendations(results)
        
        print("\n" + "="*80)
        print(f"{self.colors['BOLD']}Scan finalizado!{self.colors['RESET']}")
        print("="*80)
    
    def _display_risk_statistics(self, results: Dict):
        """Exibe estatísticas por nível de risco"""
        targets = results.get('targets', [])
        
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for target_data in targets:
            risk_level = target_data.get('risk_assessment', {}).get('risk_level', 'INFO')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        print(f"\n{self.colors['BOLD']}⚠️  DISTRIBUIÇÃO DE RISCOS{self.colors['RESET']}")
        
        for risk, count in risk_counts.items():
            if count > 0:
                color = self.colors.get(risk, self.colors['RESET'])
                print(f"  {color}{risk}{self.colors['RESET']}: {count} alvo(s)")
    
    def _display_target_summary(self, target_data: Dict, index: int, total: int):
        """Exibe resumo de um alvo específico"""
        target = target_data.get('target', 'Unknown')
        risk_assessment = target_data.get('risk_assessment', {})
        risk_level = risk_assessment.get('risk_level', 'INFO')
        risk_score = risk_assessment.get('risk_score', 0)
        risk_color = self.colors.get(risk_level, self.colors['RESET'])
        print(f"\n[{index}/{total}] {self.colors['BOLD']}{target}{self.colors['RESET']}")
        print(f"    Risco: {risk_color}{risk_level}{self.colors['RESET']} (Score: {risk_score})")
        # Portas abertas e serviços
        nmap_data = target_data.get('nmap_scan', {})
        open_ports = nmap_data.get('open_ports', [])
        services = nmap_data.get('services', {})
        if open_ports:
            print(f"    Portas Abertas: {', '.join(map(str, open_ports[:10]))}")
            for port in open_ports:
                if port in services:
                    svc = services[port]
                    print(f"      - {port}/tcp: {svc.get('service','?')} {svc.get('version','')}")
        # Tempo por host
        if 'scan_time' in target_data:
            print(f"    Tempo de scan: {target_data['scan_time']:.2f} segundos")
        # Serviços expostos
        banner_data = target_data.get('banners', {})
        exposed_services = banner_data.get('exposed_services', [])
        if exposed_services:
            print(f"    Serviços Expostos: {len(exposed_services)}")
            for service in exposed_services[:3]:
                print(f"      • {service}")
            if len(exposed_services) > 3:
                print(f"      • ... e mais {len(exposed_services)-3} serviços")
        # Tecnologias identificadas
        footprint = target_data.get('footprint', {})
        tech_stack = footprint.get('technology_stack', {})
        if tech_stack:
            self._display_technology_stack(tech_stack)
        # Resultados do Metasploit
        metasploit_data = target_data.get('metasploit_scan', {})
        if metasploit_data and not metasploit_data.get('disabled') and not metasploit_data.get('error'):
            self._display_metasploit_results(metasploit_data)
        
        # Vulnerabilidades críticas
        vuln_assessment = footprint.get('vulnerability_assessment', {})
        known_vulns = vuln_assessment.get('known_vulnerabilities', [])
        if known_vulns:
            print(f"    {self.colors['HIGH']}⚠️  Vulnerabilidades Conhecidas: {len(known_vulns)}{self.colors['RESET']}")
            for vuln in known_vulns[:2]:
                print(f"      • {vuln}")
            if len(known_vulns) > 2:
                print(f"      • ... e mais {len(known_vulns)-2} vulnerabilidades")
        
        findings = risk_assessment.get('findings', [])
        if findings:
            print(f"    {self.colors['HIGH']}🔍 Principais Achados:{self.colors['RESET']}")
            for finding in findings[:3]:
                print(f"      • {finding}")
    
    def _display_metasploit_results(self, metasploit_data: Dict):
        """Exibe resultados detalhados do Metasploit com informações completas"""
        mode = metasploit_data.get('mode', 'unknown')
        status = metasploit_data.get('status', 'unknown')
        
        if status == 'error':
            print(f"    {self.colors['HIGH']}❌ Metasploit: {metasploit_data.get('message', 'Erro desconhecido')}{self.colors['RESET']}")
            return
        
        # Cabeçalho do Metasploit com mais informações
        mode_icons = {
            'verify': '🔍',
            'aggressive': '⚡',
            'redteam': '🎯',
            'bugbounty': '💰'
        }
        mode_names = {
            'verify': 'Verificação',
            'aggressive': 'Agressivo',
            'redteam': 'Red Team',
            'bugbounty': 'Bug Bounty'
        }
        
        mode_icon = mode_icons.get(mode, "🔧")
        mode_name = mode_names.get(mode, "Auxiliar")
        print(f"    {self.colors['BOLD']}{mode_icon} ANÁLISE METASPLOIT ({mode_name.upper()}):{self.colors['RESET']}")
        
        # Estatísticas do scan
        scan_summary = metasploit_data.get('scan_summary', {})
        if scan_summary:
            ports_scanned = scan_summary.get('ports_scanned', 0)
            modules_tested = scan_summary.get('modules_tested', 0)
            exploits_found = scan_summary.get('exploits_found', 0)
            high_risk = scan_summary.get('high_risk_exploits', 0)
            
            print(f"      📊 Portas analisadas: {self.colors['INFO']}{ports_scanned}{self.colors['RESET']}")
            print(f"      🔧 Módulos testados: {self.colors['INFO']}{modules_tested}{self.colors['RESET']}")
            print(f"      🎯 Exploits encontrados: {self.colors['MEDIUM']}{exploits_found}{self.colors['RESET']}")
            if high_risk > 0:
                print(f"      🚨 Exploits CRÍTICOS: {self.colors['HIGH']}{high_risk}{self.colors['RESET']}")
            
            # Estatísticas específicas por modo
            if mode in ['aggressive', 'redteam']:
                brute_attempts = scan_summary.get('brute_force_attempts', 0)
                if brute_attempts > 0:
                    print(f"      🔓 Ataques de força bruta: {self.colors['MEDIUM']}{brute_attempts}{self.colors['RESET']}")
            
            if mode == 'bugbounty':
                web_vulns = scan_summary.get('web_vulnerabilities', 0)
                cve_matches = scan_summary.get('cve_matches', 0)
                if web_vulns > 0:
                    print(f"      🌐 Vulnerabilidades web: {self.colors['HIGH']}{web_vulns}{self.colors['RESET']}")
                if cve_matches > 0:
                    print(f"      🎯 CVEs identificados: {self.colors['HIGH']}{cve_matches}{self.colors['RESET']}")
        
        # Exploits disponíveis com detalhes
        exploits_available = metasploit_data.get('exploits_available', [])
        if exploits_available:
            print(f"\n      {self.colors['HIGH']}🚨 EXPLOITS DETECTADOS ({len(exploits_available)}):{self.colors['RESET']}")
            for i, exploit in enumerate(exploits_available[:5], 1):
                port = exploit.get('port', '?')
                module = exploit.get('module', 'unknown')
                confidence = exploit.get('confidence', 'unknown')
                risk_level = exploit.get('risk_level', 'MEDIUM')
                description = exploit.get('description', 'N/A')
                cve_refs = exploit.get('cve_references', [])
                
                risk_color = self.colors.get(risk_level, self.colors['RESET'])
                print(f"        [{i}] Porta {port}: {risk_color}{risk_level}{self.colors['RESET']}")
                print(f"            Módulo: {module}")
                print(f"            Confiança: {confidence}")
                if description != 'N/A':
                    print(f"            Descrição: {description[:60]}{'...' if len(description) > 60 else ''}")
                if cve_refs:
                    print(f"            CVE: {', '.join(cve_refs[:2])}")
                
                # Informações específicas por modo
                if mode == 'redteam' and exploit.get('redteam_priority'):
                    print(f"            {self.colors['HIGH']}🎯 Prioridade Red Team: {exploit.get('redteam_priority')}{self.colors['RESET']}")
                
                if mode == 'bugbounty' and exploit.get('bounty_potential'):
                    print(f"            {self.colors['HIGH']}💰 Potencial Bounty: {exploit.get('bounty_potential')}{self.colors['RESET']}")
                
                if risk_level in ['HIGH', 'CRITICAL']:
                    print(f"            {self.colors['HIGH']}⚠️  AÇÃO REQUERIDA: Aplicar patches imediatamente!{self.colors['RESET']}")
                print()
            
            if len(exploits_available) > 5:
                print(f"        ... e mais {len(exploits_available)-5} exploits")
        
        # Resultados de Brute Force (modos agressivos)
        brute_force_results = metasploit_data.get('brute_force_results', [])
        if brute_force_results and mode in ['aggressive', 'redteam']:
            successful_brute = [b for b in brute_force_results if b.get('status') == 'SUCCESS']
            print(f"\n      {self.colors['MEDIUM']}🔓 ATAQUES DE FORÇA BRUTA ({len(brute_force_results)}):{self.colors['RESET']}")
            print(f"        Sucessos: {self.colors['HIGH']}{len(successful_brute)}{self.colors['RESET']} | "
                  f"Falhas: {self.colors['LOW']}{len(brute_force_results) - len(successful_brute)}{self.colors['RESET']}")
            
            for brute in successful_brute[:3]:
                port = brute.get('port', '?')
                service = brute.get('service', 'unknown')
                credentials = brute.get('credentials_found', {})
                
                print(f"        🚨 Porta {port} ({service}): {self.colors['HIGH']}CREDENCIAIS ENCONTRADAS{self.colors['RESET']}")
                if credentials:
                    username = credentials.get('username', 'N/A')
                    password = credentials.get('password', 'N/A')
                    print(f"           {self.colors['HIGH']}👤 {username}:{password}{self.colors['RESET']}")
        
        # Vulnerabilidades Web (Bug Bounty)
        web_vulnerabilities = metasploit_data.get('web_vulnerabilities', [])
        if web_vulnerabilities and mode == 'bugbounty':
            print(f"\n      {self.colors['HIGH']}🌐 VULNERABILIDADES WEB ({len(web_vulnerabilities)}):{self.colors['RESET']}")
            for i, vuln in enumerate(web_vulnerabilities[:3], 1):
                vuln_type = vuln.get('type', 'unknown')
                severity = vuln.get('severity', 'MEDIUM')
                port = vuln.get('port', '?')
                bounty_value = vuln.get('estimated_bounty', 'N/A')
                
                severity_color = self.colors.get(severity, self.colors['RESET'])
                print(f"        [{i}] {vuln_type}: {severity_color}{severity}{self.colors['RESET']}")
                print(f"            Porta: {port}")
                if bounty_value != 'N/A':
                    print(f"            {self.colors['HIGH']}💰 Valor estimado: {bounty_value}{self.colors['RESET']}")
        
        # CVEs Identificados (Bug Bounty)
        cve_matches = metasploit_data.get('cve_matches', [])
        if cve_matches and mode == 'bugbounty':
            print(f"\n      {self.colors['HIGH']}🎯 CVEs IDENTIFICADOS ({len(cve_matches)}):{self.colors['RESET']}")
            for cve in cve_matches[:3]:
                cve_id = cve.get('cve', 'N/A')
                description = cve.get('description', 'N/A')
                bounty_potential = cve.get('bounty_potential', 'N/A')
                
                print(f"        🚨 {cve_id}")
                if description != 'N/A':
                    print(f"           {description[:80]}{'...' if len(description) > 80 else ''}")
                if bounty_potential != 'N/A':
                    print(f"           {self.colors['HIGH']}💰 Potencial: {bounty_potential}{self.colors['RESET']}")
        
        # Enumeração Avançada (Red Team)
        enumeration_results = metasploit_data.get('enumeration_results', [])
        if enumeration_results and mode == 'redteam':
            print(f"\n      {self.colors['INFO']}📋 ENUMERAÇÃO AVANÇADA ({len(enumeration_results)}):{self.colors['RESET']}")
            for enum in enumeration_results[:3]:
                enum_type = enum.get('type', 'unknown')
                port = enum.get('port', '?')
                
                print(f"        📋 Porta {port}: {enum_type}")
                
                if enum.get('shares_found'):
                    shares = ', '.join(enum['shares_found'][:3])
                    print(f"           Shares: {self.colors['MEDIUM']}{shares}{self.colors['RESET']}")
                
                if enum.get('users_found'):
                    users = ', '.join(enum['users_found'][:3])
                    print(f"           Usuários: {self.colors['MEDIUM']}{users}{self.colors['RESET']}")
                
                if enum.get('directories'):
                    dirs = ', '.join(enum['directories'][:3])
                    print(f"           Diretórios: {self.colors['MEDIUM']}{dirs}{self.colors['RESET']}")
        
        # Exploits testados (modo exploit)
        exploits_tested = metasploit_data.get('exploits_tested', [])
        if exploits_tested:
            vulnerable_count = sum(1 for test in exploits_tested if test.get('vulnerable', False))
            print(f"\n      {self.colors['MEDIUM']}⚡ EXPLOITS TESTADOS ({len(exploits_tested)}):{self.colors['RESET']}")
            print(f"        Vulneráveis: {self.colors['HIGH']}{vulnerable_count}{self.colors['RESET']} | "
                  f"Seguros: {self.colors['LOW']}{len(exploits_tested) - vulnerable_count}{self.colors['RESET']}")
            
            for test in exploits_tested[:3]:
                vulnerable = test.get('vulnerable', False)
                module = test.get('module', 'unknown')
                port = test.get('port', '?')
                cve = test.get('cve', 'N/A')
                severity = test.get('severity', 'MEDIUM')
                
                if vulnerable:
                    status_icon = "🚨"
                    status_text = "VULNERÁVEL"
                    status_color = self.colors['HIGH']
                else:
                    status_icon = "✅"
                    status_text = "SEGURO"
                    status_color = self.colors['LOW']
                
                print(f"        {status_icon} Porta {port}: {module}")
                print(f"           Status: {status_color}{status_text}{self.colors['RESET']}")
                if cve != 'N/A':
                    print(f"           CVE: {cve}")
                if vulnerable and severity:
                    severity_color = self.colors.get(severity, self.colors['RESET'])
                    print(f"           Severidade: {severity_color}{severity}{self.colors['RESET']}")
        
        # Vulnerabilidades confirmadas
        vulnerabilities = metasploit_data.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n      {self.colors['HIGH']}🚨 VULNERABILIDADES CONFIRMADAS ({len(vulnerabilities)}):{self.colors['RESET']}")
            for vuln in vulnerabilities[:3]:
                port = vuln.get('port', '?')
                exploit = vuln.get('exploit', 'unknown')
                severity = vuln.get('severity', 'MEDIUM')
                cve = vuln.get('cve', 'N/A')
                impact = vuln.get('impact', 'N/A')
                recommendation = vuln.get('recommendation', '')
                
                severity_color = self.colors.get(severity, self.colors['RESET'])
                print(f"        🚨 Porta {port}: {severity_color}{severity}{self.colors['RESET']}")
                print(f"           Exploit: {exploit}")
                if cve != 'N/A':
                    print(f"           CVE: {cve}")
                if impact != 'N/A':
                    print(f"           Impacto: {impact}")
                if recommendation:
                    print(f"           {self.colors['MEDIUM']}💡 {recommendation}{self.colors['RESET']}")
                print()
        
        # Resultados auxiliares detalhados
        auxiliary_results = metasploit_data.get('auxiliary_results', [])
        if auxiliary_results:
            successful = [aux for aux in auxiliary_results if aux.get('status') == 'success']
            failed = [aux for aux in auxiliary_results if aux.get('status') != 'success']
            
            print(f"\n      {self.colors['INFO']}🔧 SCANS AUXILIARES ({len(auxiliary_results)}):{self.colors['RESET']}")
            print(f"        Sucessos: {self.colors['LOW']}{len(successful)}{self.colors['RESET']} | "
                  f"Falhas: {self.colors['MEDIUM']}{len(failed)}{self.colors['RESET']}")
            
            # Mostrar sucessos
            for aux in successful[:3]:
                module = aux.get('module', 'unknown')
                port = aux.get('port', '?')
                service_detected = aux.get('service_detected', '')
                version = aux.get('version', '')
                info = aux.get('info', 'N/A')
                
                print(f"        ✅ Porta {port}: {module}")
                if service_detected:
                    print(f"           Serviço: {self.colors['INFO']}{service_detected} {version}{self.colors['RESET']}")
                if info != 'N/A':
                    print(f"           Info: {info}")
                
                # Informações específicas
                if aux.get('directories_found'):
                    dirs = ', '.join(aux['directories_found'][:3])
                    print(f"           Diretórios: {dirs}")
                if aux.get('ssl_info'):
                    ssl = aux['ssl_info']
                    print(f"           SSL: {ssl.get('protocol', 'N/A')} - {ssl.get('cipher', 'N/A')}")
        
        # Avisos de segurança
        warnings = metasploit_data.get('warnings', [])
        if warnings:
            print(f"\n      {self.colors['MEDIUM']}⚠️  AVISOS DE SEGURANÇA:{self.colors['RESET']}")
            for warning in warnings[:2]:
                print(f"        • {warning}")
        
        # Resumo final com informações específicas por modo
        total_issues = len(exploits_available) + len(vulnerabilities)
        if mode in ['aggressive', 'redteam'] and brute_force_results:
            total_issues += len([b for b in brute_force_results if b.get('status') == 'SUCCESS'])
        if mode == 'bugbounty' and web_vulnerabilities:
            total_issues += len(web_vulnerabilities)
        
        if total_issues > 0:
            print(f"\n      {self.colors['HIGH']}📋 RESUMO: {total_issues} problema(s) de segurança detectado(s){self.colors['RESET']}")
            if mode == 'bugbounty':
                print(f"        {self.colors['MEDIUM']}💰 Recomenda-se análise para potencial bug bounty{self.colors['RESET']}")
            elif mode == 'redteam':
                print(f"        {self.colors['MEDIUM']}🎯 Vetores de ataque identificados para Red Team{self.colors['RESET']}")
            else:
                print(f"        {self.colors['MEDIUM']}💡 Recomenda-se revisão imediata e aplicação de patches{self.colors['RESET']}")
        else:
            print(f"\n      {self.colors['LOW']}✅ RESUMO: Nenhum problema crítico de segurança detectado{self.colors['RESET']}")
            print(f"        {self.colors['INFO']}ℹ️  Alvo aparenta estar seguro contra exploits conhecidos{self.colors['RESET']}")
    
    def _display_technology_stack(self, tech_stack: Dict):
        """Exibe stack tecnológico identificado"""
        tech_items = []
        
        # Coletar tecnologias relevantes
        for category, items in tech_stack.items():
            if category == 'confidence_scores':
                continue
            
            if isinstance(items, list) and items:
                for item in items[:2]:  # Limitar quantidade
                    if isinstance(item, dict):
                        tech_name = item.get('type', str(item))
                        version = item.get('version', '')
                        if version:
                            tech_items.append(f"{tech_name} {version}")
                        else:
                            tech_items.append(tech_name)
                    else:
                        tech_items.append(str(item))
        
        if tech_items:
            tech_str = ', '.join(tech_items[:4])  # Mostrar até 4 tecnologias
            print(f"    Tecnologias: {tech_str}")
    
    def _display_general_recommendations(self, results: Dict):
        """Exibe recomendações gerais"""
        targets = results.get('targets', [])
        
        # Coletar todas as recomendações
        all_recommendations = set()
        
        for target_data in targets:
            footprint = target_data.get('footprint', {})
            recommendations = footprint.get('recommendations', [])
            all_recommendations.update(recommendations[:5])  # Limitar por alvo
        
        if all_recommendations:
            print(f"\n{self.colors['BOLD']}💡 RECOMENDAÇÕES GERAIS{self.colors['RESET']}")
            for i, recommendation in enumerate(list(all_recommendations)[:8], 1):  # Top 8
                print(f"  {i}. {recommendation}")
    
    def display_target_details(self, target_data: Dict):
        """Exibe detalhes completos de um alvo"""
        target = target_data.get('target', 'Unknown')
        
        print(f"\n{self.colors['BOLD']}{self.colors['UNDERLINE']}DETALHES COMPLETOS: {target}{self.colors['RESET']}")
        print("="*60)
        
        # Risk Assessment
        risk_assessment = target_data.get('risk_assessment', {})
        if risk_assessment:
            print(f"\n{self.colors['BOLD']}🔍 AVALIAÇÃO DE RISCO{self.colors['RESET']}")
            risk_level = risk_assessment.get('risk_level', 'INFO')
            risk_color = self.colors.get(risk_level, self.colors['RESET'])
            print(f"  Nível: {risk_color}{risk_level}{self.colors['RESET']}")
            print(f"  Score: {risk_assessment.get('risk_score', 0)}")
            
            findings = risk_assessment.get('findings', [])
            if findings:
                print("  Achados:")
                for finding in findings:
                    print(f"    • {finding}")
        
        # Nmap Scan
        nmap_data = target_data.get('nmap_scan', {})
        if nmap_data and not nmap_data.get('audit_mode'):
            print(f"\n{self.colors['BOLD']}🔍 SCAN NMAP{self.colors['RESET']}")
            
            open_ports = nmap_data.get('open_ports', [])
            if open_ports:
                print(f"  Portas Abertas: {', '.join(map(str, open_ports))}")
            
            services = nmap_data.get('services', {})
            if services:
                print("  Serviços Detectados:")
                for port, service_info in services.items():
                    service_name = service_info.get('service', 'unknown')
                    version = service_info.get('version', '')
                    print(f"    {port}/tcp: {service_name} {version}")
        
        # WHOIS Info
        whois_info = target_data.get('whois_info', {})
        if whois_info:
            print(f"\n{self.colors['BOLD']}🌐 INFORMAÇÕES WHOIS{self.colors['RESET']}")
            
            if whois_info.get('is_ip'):
                ip_info = whois_info.get('ip_info', {})
                org = ip_info.get('organization', 'N/A')
                country = ip_info.get('country', 'N/A')
                print(f"  Organização: {org}")
                print(f"  País: {country}")
            else:
                domain_info = whois_info.get('domain_info', {})
                registrar = domain_info.get('registrar', 'N/A')
                creation_date = domain_info.get('creation_date', 'N/A')
                print(f"  Registrar: {registrar}")
                print(f"  Criado em: {creation_date}")
        
        # Banner Information
        banner_data = target_data.get('banners', {})
        if banner_data and not banner_data.get('audit_mode'):
            print(f"\n{self.colors['BOLD']}🏷️  BANNERS COLETADOS{self.colors['RESET']}")
            
            banners = banner_data.get('banners', {})
            for port, banner_info in banners.items():
                service = banner_info.get('service', 'unknown')
                banner = banner_info.get('banner', '')
                risk = banner_info.get('risk_level', 'LOW')
                
                risk_color = self.colors.get(risk, self.colors['RESET'])
                print(f"  Porta {port} ({service}) - Risco: {risk_color}{risk}{self.colors['RESET']}")
                
                if banner:
                    # Mostrar apenas primeira linha do banner
                    banner_line = banner.split('\n')[0].strip()
                    if len(banner_line) > 60:
                        banner_line = banner_line[:57] + "..."
                    print(f"    Banner: {banner_line}")
        
        # Footprint Analysis
        footprint = target_data.get('footprint', {})
        if footprint:
            print(f"\n{self.colors['BOLD']}👣 ANÁLISE DE FOOTPRINT{self.colors['RESET']}")
            
            # Technology Stack
            tech_stack = footprint.get('technology_stack', {})
            if tech_stack:
                print("  Stack Tecnológico:")
                for category, items in tech_stack.items():
                    if category == 'confidence_scores' or not items:
                        continue
                    
                    category_name = category.replace('_', ' ').title()
                    print(f"    {category_name}:")
                    
                    for item in items[:3]:  # Limitar exibição
                        if isinstance(item, dict):
                            tech_name = item.get('type', str(item))
                            version = item.get('version', '')
                            if version:
                                print(f"      • {tech_name} {version}")
                            else:
                                print(f"      • {tech_name}")
                        else:
                            print(f"      • {item}")
            
            # Vulnerability Assessment
            vuln_assessment = footprint.get('vulnerability_assessment', {})
            if vuln_assessment:
                known_vulns = vuln_assessment.get('known_vulnerabilities', [])
                if known_vulns:
                    print(f"  {self.colors['HIGH']}Vulnerabilidades Conhecidas:{self.colors['RESET']}")
                    for vuln in known_vulns[:5]:  # Top 5
                        print(f"    • {vuln}")
                
                critical_services = vuln_assessment.get('critical_services', [])
                if critical_services:
                    print("  Serviços Críticos:")
                    for service in critical_services:
                        print(f"    • {service}")
    
    def display_json(self, data: Dict):
        """Exibe dados em formato JSON"""
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    
    def display_progress(self, current: int, total: int, target: str):
        """Exibe progresso do scan"""
        percentage = (current / total) * 100
        bar_length = 30
        filled_length = int(bar_length * current // total)
        
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        print(f"\r[{bar}] {percentage:.1f}% ({current}/{total}) - Escaneando: {target[:30]}", end='', flush=True)
        
        if current == total:
            print()  # Nova linha ao finalizar