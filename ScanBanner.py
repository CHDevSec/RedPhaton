#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Banner Scanner & Footprinting Tool
Ferramenta para revalidação de endpoints e coleta de banners expostos
Desenvolvido para testes de segurança autorizados
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path
import shutil

# Importar módulos locais
sys.path.append(str(Path(__file__).parent))

from modules.nmap_scanner import NmapScanner
from modules.whois_scanner import WhoisScanner
from modules.banner_collector import BannerCollector
from modules.footprint_analyzer import FootprintAnalyzer
from modules.nuclei_scanner import NucleiScanner
from modules.metasploit_scanner import MetasploitScanner
from modules.blackhat_exploits import BlackHatExploits
from modules.advanced_evasion import AdvancedEvasion
from modules.ai_exploit_engine import AIExploitEngine
from modules.polyglot_fuzzer import PolyglotFuzzer
from modules.lateral_movement import LateralMovement
from modules.automated_exploitation import AutomatedExploitation
from modules.osint_reconnaissance import OSINTReconnaissance
from modules.stealth_evasion import StealthEvasion
from modules.zero_day_discovery import ZeroDayDiscoveryEngine
from modules.c2_framework import C2Framework
from modules.advanced_persistence import AdvancedPersistence
from modules.memory_corruption_exploits import MemoryCorruptionExploits
from modules.kernel_exploits import KernelExploits
from modules.advanced_payloads import AdvancedPayloads
from utils.file_handler import FileHandler
from utils.output_formatter import OutputFormatter
from utils.logger import SecurityLogger
from banner_function import display_banner, display_help_banner

class BannerScanTool:
    """Classe principal para coordenação dos scans de banner e footprint"""
    
    def __init__(self, verbose=False, audit_mode=False, nuclei_mode='comprehensive', nuclei_tags=None, metasploit_mode='off', metasploit_confirm=False, aggressive_mode=False):
        self.verbose = verbose
        self.audit_mode = audit_mode
        self.nuclei_mode = nuclei_mode
        self.nuclei_tags = nuclei_tags
        self.metasploit_mode = metasploit_mode
        self.metasploit_confirm = metasploit_confirm
        self.aggressive_mode = aggressive_mode
        
        # Configurar logger
        self.logger = SecurityLogger(verbose=verbose)
        self.file_handler = FileHandler()
        self.output_formatter = OutputFormatter()
        
        # Inicializar scanners
        self.nmap_scanner = NmapScanner(logger=self.logger)
        self.whois_scanner = WhoisScanner(logger=self.logger)
        self.banner_collector = BannerCollector(logger=self.logger)
        self.footprint_analyzer = FootprintAnalyzer(logger=self.logger)
        self.nuclei_scanner = NucleiScanner(logger=self.logger)
        self.metasploit_scanner = MetasploitScanner(logger=self.logger)
        
        # 🔥 NOVOS MÓDULOS BLACK HAT 🔥
        self.blackhat_exploits = BlackHatExploits(logger=self.logger)
        self.advanced_evasion = AdvancedEvasion(logger=self.logger)
        self.ai_exploit_engine = AIExploitEngine(logger=self.logger)
        self.polyglot_fuzzer = PolyglotFuzzer(logger=self.logger)
        self.lateral_movement = LateralMovement(logger=self.logger)
        self.automated_exploitation = AutomatedExploitation(logger=self.logger)
        self.osint_reconnaissance = OSINTReconnaissance(logger=self.logger)
        self.stealth_evasion = StealthEvasion(logger=self.logger)
        
        # 🕳️ NOVOS MÓDULOS EXPERT 🕳️
        self.zero_day_discovery = ZeroDayDiscoveryEngine(logger=self.logger)
        self.c2_framework = C2Framework(logger=self.logger)
        self.advanced_persistence = AdvancedPersistence(logger=self.logger)
        
        # 💀 MÓDULOS NÍVEL 10/10 💀
        self.memory_corruption = MemoryCorruptionExploits(logger=self.logger)
        self.kernel_exploits = KernelExploits(logger=self.logger)
        self.advanced_payloads = AdvancedPayloads(logger=self.logger)
        
        # Configurar modo agressivo
        if self.aggressive_mode:
            self.logger.warning("MODO AGRESSIVO ATIVADO - Use apenas em ambientes autorizados!")
            if self.nuclei_mode == 'comprehensive':
                self.nuclei_mode = 'aggressive'
            if self.metasploit_mode == 'verify':
                self.metasploit_mode = 'aggressive'
        
        self.results = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'mode': 'audit' if audit_mode else 'exec',
                'verbose': verbose,
                'scan_type': 'aggressive' if aggressive_mode else 'comprehensive',
                'aggressive_mode': aggressive_mode
            },
            'targets': [],
            'summary': {}
        }
    
    def scan_single_target(self, target):
        """Realiza scan completo em um único alvo"""
        self.logger.info(f"Iniciando scan do alvo: {target}")
        
        target_result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'nmap_scan': {},
            'whois_info': {},
            'banners': {},
            'nuclei_scan': {},
            'metasploit_scan': {},
            'footprint': {},
            'risk_assessment': {},
            'blackhat_exploits': {},
            'evasion_results': {},
            'ai_analysis': {},
            'polyglot_fuzzing': {},
            'lateral_movement': {},
            'zero_day_discovery': {},
            'c2_deployment': {},
            'advanced_persistence': {}
        }
        
        try:
            # 1. Nmap Scan (portas e serviços)
            if not self.audit_mode:
                self.logger.info(f"Executando Nmap scan em {target}")
                target_result['nmap_scan'] = self.nmap_scanner.scan_target(target)
            else:
                self.logger.info(f"[AUDIT] Simulando Nmap scan em {target}")
                target_result['nmap_scan'] = {'audit_mode': True}
            
            # 2. Whois Lookup
            self.logger.info(f"Executando Whois lookup em {target}")
            target_result['whois_info'] = self.whois_scanner.lookup_target(target)
            
            # 3. Banner Collection
            if not self.audit_mode:
                self.logger.info(f"Coletando banners de {target}")
                target_result['banners'] = self.banner_collector.collect_banners(target)
            else:
                self.logger.info(f"[AUDIT] Simulando coleta de banners em {target}")
                target_result['banners'] = {'audit_mode': True}
            
            # 4. Nuclei Vulnerability Scan
            if self.nuclei_mode != 'off':
                if not self.audit_mode and self.nuclei_scanner.is_available():
                    if self.nuclei_tags:
                        self.logger.info(f"Executando scan Nuclei com tags específicas em {target}")
                        target_result['nuclei_scan'] = self.nuclei_scanner.scan_with_custom_templates(
                            target, self.nuclei_tags.split(',')
                        )
                    else:
                        self.logger.info(f"Executando scan Nuclei ({self.nuclei_mode}) em {target}")
                        target_result['nuclei_scan'] = self.nuclei_scanner.scan_target(target, self.nuclei_mode)
                else:
                    if self.audit_mode:
                        self.logger.info(f"[AUDIT] Simulando scan Nuclei em {target}")
                        target_result['nuclei_scan'] = {'audit_mode': True}
                    else:
                        self.logger.warning(f"Nuclei não disponível - pulando scan de vulnerabilidades")
                        target_result['nuclei_scan'] = {'error': 'Nuclei não encontrado'}
            else:
                self.logger.info(f"Scan Nuclei desabilitado para {target}")
                target_result['nuclei_scan'] = {'disabled': True}
            
            # 5. Metasploit Exploit Verification
            if self.metasploit_mode != 'off':
                if not self.audit_mode and self.metasploit_scanner.is_available():
                    # Verificar se é modo exploit e se tem confirmação
                    if self.metasploit_mode == 'exploit' and not self.metasploit_confirm:
                        self.logger.warning(f"Modo exploit requer confirmação explícita - usando modo verify")
                        scan_mode = 'verify'
                    else:
                        scan_mode = self.metasploit_mode
                    
                    # Extrair portas abertas do scan Nmap
                    open_ports = []
                    if 'open_ports' in target_result.get('nmap_scan', {}):
                        open_ports = target_result['nmap_scan']['open_ports']
                    
                    if open_ports:
                        self.logger.info(f"Executando scan Metasploit ({scan_mode}) em {target}")
                        target_result['metasploit_scan'] = self.metasploit_scanner.scan_target(
                            target, open_ports, scan_mode
                        )
                    else:
                        self.logger.info(f"Nenhuma porta aberta encontrada - pulando scan Metasploit")
                        target_result['metasploit_scan'] = {'info': 'Nenhuma porta aberta'}
                else:
                    if self.audit_mode:
                        self.logger.info(f"[AUDIT] Simulando scan Metasploit em {target}")
                        target_result['metasploit_scan'] = {'audit_mode': True}
                    else:
                        self.logger.warning(f"Metasploit não disponível - pulando verificação de exploits")
                        target_result['metasploit_scan'] = {'error': 'Metasploit não encontrado'}
            else:
                self.logger.info(f"Scan Metasploit desabilitado para {target}")
                target_result['metasploit_scan'] = {'disabled': True}
            
            # 6. Footprint Analysis
            self.logger.info(f"Analisando footprint de {target}")
            target_result['footprint'] = self.footprint_analyzer.analyze_target(
                target, target_result['nmap_scan'], target_result['banners']
            )
            
            # 7. 🔥 BLACK HAT EXPLOITS SCAN 🔥
            if self.aggressive_mode and not self.audit_mode:
                self.logger.warning(f"🔥 INICIANDO SCAN BLACK HAT em {target}")
                open_ports = target_result.get('nmap_scan', {}).get('open_ports', [])
                if open_ports:
                    target_result['blackhat_exploits'] = self.blackhat_exploits.scan_for_zero_days(target, open_ports)
                    
                    # 🎭 TESTE DE EVASÃO DE WAF
                    if target_result.get('banners', {}).get('web_banners'):
                        for port, web_info in target_result['banners']['web_banners'].items():
                            if web_info.get('status_code') == 200:
                                protocol = 'https' if port in [443, 8443] else 'http'
                                test_url = f"{protocol}://{target}:{port}"
                                
                                # Teste de evasão
                                evasion_results = self.advanced_evasion.bypass_waf(test_url, "<script>alert(1)</script>")
                                target_result['evasion_results'][port] = evasion_results
                                break
                    
                    # 🧠 ANÁLISE DE IA
                    if target_result.get('banners', {}).get('web_banners'):
                        for port, web_info in target_result['banners']['web_banners'].items():
                            if web_info.get('status_code') == 200:
                                protocol = 'https' if port in [443, 8443] else 'http'
                                test_url = f"{protocol}://{target}:{port}"
                                
                                ai_results = self.ai_exploit_engine.intelligent_vulnerability_scan(test_url)
                                target_result['ai_analysis'][port] = ai_results
                                break
                    
                    # 🎯 POLYGLOT FUZZING
                    if target_result.get('banners', {}).get('web_banners'):
                        for port, web_info in target_result['banners']['web_banners'].items():
                            if web_info.get('status_code') == 200:
                                protocol = 'https' if port in [443, 8443] else 'http'
                                test_url = f"{protocol}://{target}:{port}"
                                
                                # Fuzzing inteligente
                                fuzz_results = self.polyglot_fuzzer.intelligent_fuzz(test_url, max_payloads=50)
                                target_result['polyglot_fuzzing'][port] = fuzz_results
                                
                                # Teste de coleção de políglotas
                                polyglot_collection = self.polyglot_fuzzer.test_polyglot_collection(test_url)
                                target_result['polyglot_fuzzing'][f'{port}_collection'] = polyglot_collection
                                break
                    
                    # 🔗 LATERAL MOVEMENT (se múltiplas portas abertas)
                    if len(open_ports) >= 2:  # Potencial para movimento lateral
                        lateral_results = self.lateral_movement.auto_pivot_scan(target, max_depth=2)
                        target_result['lateral_movement'] = lateral_results
                        
                        # Harvest de credenciais
                        cred_harvest = self.lateral_movement.credential_harvesting(target)
                        target_result['lateral_movement']['credentials_harvested'] = cred_harvest
            
            # 8. 💀 AUTO-EXPLORAÇÃO (se habilitado)
            if hasattr(self, 'auto_exploit_mode') and self.auto_exploit_mode:
                self.logger.warning(f"💀 INICIANDO AUTO-EXPLORAÇÃO em {target}")
                
                # Coletar vulnerabilidades encontradas
                vulnerabilities = []
                
                # Adicionar resultados do Nuclei se existirem
                if 'nuclei_scan' in target_result:
                    nuclei_vulns = target_result['nuclei_scan'].get('vulnerabilities', [])
                    for vuln in nuclei_vulns:
                        vulnerabilities.append({
                            'type': vuln.get('info', {}).get('name', 'Unknown'),
                            'severity': vuln.get('info', {}).get('severity', 'info'),
                            'source': 'nuclei'
                        })
                
                # Adicionar vulnerabilidades da IA
                if 'ai_analysis' in target_result:
                    for port_vulns in target_result['ai_analysis'].values():
                        if isinstance(port_vulns, list):
                            for vuln in port_vulns:
                                vulnerabilities.append({
                                    'type': vuln.type,
                                    'severity': vuln.severity,
                                    'source': 'ai'
                                })
                
                # Executar auto-exploração
                if vulnerabilities:
                    exploit_results = self.automated_exploitation.exploit_vulnerabilities(target, vulnerabilities)
                    target_result['automated_exploitation'] = exploit_results
                    
                    # Gerar PoCs se solicitado
                    if hasattr(self, 'generate_poc_mode') and self.generate_poc_mode:
                        target_result['proof_of_concepts'] = []
                        for exploit in exploit_results:
                            if exploit.get('status') == 'EXPLOITED':
                                poc = self.automated_exploitation.generate_poc(exploit)
                                target_result['proof_of_concepts'].append({
                                    'vulnerability': exploit.get('vulnerability_type'),
                                    'poc': poc
                                })
            
            # 9. 🕵️ RECONHECIMENTO OSINT (se habilitado)
            if hasattr(self, 'osint_mode') and self.osint_mode:
                self.logger.info(f"🕵️ INICIANDO RECONHECIMENTO OSINT para {target}")
                osint_results = self.osint_reconnaissance.comprehensive_osint_scan(target)
                target_result['osint_reconnaissance'] = osint_results
            
            # 10. 👻 CONFIGURAÇÃO STEALTH (se habilitado)
            if hasattr(self, 'stealth_mode') and self.stealth_mode != 'normal':
                self.logger.info(f"👻 APLICANDO MODO STEALTH: {self.stealth_mode}")
                stealth_config = self.stealth_evasion.stealth_scan_mode(target, self.stealth_mode)
                target_result['stealth_configuration'] = stealth_config
            
            # 11. 🕳️ DESCOBERTA DE ZERO-DAYS (se habilitado)
            if self.aggressive_mode and hasattr(self, 'zero_day_discovery_mode') and self.zero_day_discovery_mode:
                self.logger.critical(f"🕳️ INICIANDO DESCOBERTA DE ZERO-DAYS em {target}")
                if target_result.get('banners', {}).get('web_banners'):
                    for port, web_info in target_result['banners']['web_banners'].items():
                        if web_info.get('status_code') == 200:
                            protocol = 'https' if port in [443, 8443] else 'http'
                            test_url = f"{protocol}://{target}:{port}"
                            
                            zero_days = self.zero_day_discovery.discover_zero_days(test_url, deep_scan=True)
                            target_result['zero_day_discovery'][port] = [
                                {
                                    'vulnerability_type': zd.vulnerability_type,
                                    'confidence_score': zd.confidence_score,
                                    'payload_used': zd.payload_used,
                                    'evidence': zd.evidence,
                                    'risk_level': zd.risk_level
                                } for zd in zero_days
                            ]
                            
                            if zero_days:
                                self.logger.critical(f"🕳️ {len(zero_days)} POSSÍVEIS ZERO-DAYS DESCOBERTOS!")
                            break
            
            # 12. 🎯 DEPLOYMENT C2 (se habilitado)
            if hasattr(self, 'c2_deployment_mode') and self.c2_deployment_mode and not self.audit_mode:
                self.logger.critical(f"🎯 PREPARANDO DEPLOYMENT C2 para {target}")
                
                # Criar listener
                listener_id = self.c2_framework.create_listener("https", "0.0.0.0", 8443)
                self.c2_framework.start_listener(listener_id)
                
                # Gerar beacon para o OS detectado
                detected_os = target_result.get('footprint', {}).get('operating_system', 'linux')
                beacon_payload = self.c2_framework.generate_beacon(detected_os, listener_id)
                
                target_result['c2_deployment'] = {
                    'listener_id': listener_id,
                    'beacon_generated': True,
                    'payload_size': len(beacon_payload),
                    'communication_method': 'https',
                    'target_os': detected_os
                }
                
                self.logger.success(f"🎯 C2 Framework preparado para {target}")
            
            # 13. 🔒 PERSISTÊNCIA AVANÇADA (se habilitado)
            if hasattr(self, 'persistence_mode') and self.persistence_mode and not self.audit_mode:
                self.logger.critical(f"🔒 PLANEJANDO PERSISTÊNCIA AVANÇADA em {target}")
                
                # Detectar OS e privilégios
                detected_os = target_result.get('footprint', {}).get('operating_system', 'linux')
                privilege_level = "admin" if target_result.get('lateral_movement', {}).get('admin_access') else "user"
                
                # Implementar persistência
                persistence_results = self.advanced_persistence.implement_persistence(
                    detected_os, privilege_level, stealth_level="expert"
                )
                
                target_result['advanced_persistence'] = {
                    'methods_attempted': len(persistence_results),
                    'successful_methods': len([r for r in persistence_results if r.success]),
                    'persistence_details': [
                        {
                            'method_id': r.method_id,
                            'success': r.success,
                            'evasion_score': r.detection_evasion_score,
                            'strength': r.persistence_strength,
                            'artifacts': r.artifacts_created
                        } for r in persistence_results
                    ]
                }
                
                successful = len([r for r in persistence_results if r.success])
                if successful > 0:
                    self.logger.critical(f"🔒 {successful} MÉTODOS DE PERSISTÊNCIA IMPLEMENTADOS!")
            
            # Audit mode simulations
            if self.audit_mode:
                self.logger.info(f"[AUDIT] Simulando scans avançados em {target}")
                target_result['blackhat_exploits'] = {'audit_mode': True}
                target_result['evasion_results'] = {'audit_mode': True}
                target_result['ai_analysis'] = {'audit_mode': True}
                target_result['polyglot_fuzzing'] = {'audit_mode': True}
                target_result['lateral_movement'] = {'audit_mode': True}
                target_result['zero_day_discovery'] = {'audit_mode': True}
                target_result['c2_deployment'] = {'audit_mode': True}
                target_result['advanced_persistence'] = {'audit_mode': True}
            
            # 8. Risk Assessment
            target_result['risk_assessment'] = self._assess_risk(target_result)
            
            self.results['targets'].append(target_result)
            self.logger.success(f"Scan completo para {target}")
            
        except Exception as e:
            self.logger.error(f"Erro durante scan de {target}: {str(e)}")
            target_result['error'] = str(e)
            self.results['targets'].append(target_result)
    
    def scan_from_file(self, file_path):
        """Realiza scan de múltiplos alvos a partir de arquivo"""
        self.logger.info(f"Carregando alvos do arquivo: {file_path}")
        
        targets = self.file_handler.load_targets_from_file(file_path)
        if not targets:
            self.logger.error("Nenhum alvo válido encontrado no arquivo")
            return
        
        self.logger.info(f"Encontrados {len(targets)} alvos para scan")
        
        start_time = time.time()
        for i, target in enumerate(targets, 1):
            host_start = time.time()
            self.logger.info(f"[{i}/{len(targets)}] Processando: {target}")
            # Salvar tempo por host
            before_count = len(self.results['targets'])
            self.scan_single_target(target)
            after_count = len(self.results['targets'])
            host_end = time.time()
            if after_count > before_count:
                self.results['targets'][-1]['scan_time'] = host_end - host_start
            self.logger.info(f"Tempo para {target}: {host_end - host_start:.2f} segundos")
            # Delay entre scans para evitar sobrecarga
            if i < len(targets) and not self.audit_mode:
                time.sleep(1)
        end_time = time.time()
        self.results['summary']['scan_duration'] = end_time - start_time
        self.logger.success(f"Tempo total do scan: {end_time - start_time:.2f} segundos")
    
    def _assess_risk(self, target_result):
        """Avalia o risco baseado nos resultados coletados"""
        risk_score = 0
        findings = []
        
        # Análise de portas abertas
        nmap_data = target_result.get('nmap_scan', {})
        if 'open_ports' in nmap_data:
            open_ports = len(nmap_data['open_ports'])
            if open_ports > 10:
                risk_score += 3
                findings.append(f"Muitas portas abertas ({open_ports})")
            elif open_ports > 5:
                risk_score += 2
                findings.append(f"Várias portas abertas ({open_ports})")
        
        # Análise de banners expostos
        banners = target_result.get('banners', {})
        if 'exposed_services' in banners:
            for service in banners['exposed_services']:
                if any(keyword in service.lower() for keyword in ['admin', 'root', 'default']):
                    risk_score += 2
                    findings.append(f"Banner sensível exposto: {service}")
        
        # Análise de vulnerabilidades Nuclei
        nuclei_data = target_result.get('nuclei_scan', {})
        if 'vulnerabilities' in nuclei_data:
            vuln_count = len(nuclei_data['vulnerabilities'])
            if vuln_count > 0:
                risk_score += min(vuln_count, 5)  # Máximo 5 pontos
                findings.append(f"Vulnerabilidades encontradas pelo Nuclei: {vuln_count}")
        
        # Análise de exploits Metasploit
        metasploit_data = target_result.get('metasploit_scan', {})
        if 'exploits_found' in metasploit_data:
            exploit_count = len(metasploit_data['exploits_found'])
            if exploit_count > 0:
                risk_score += exploit_count * 3  # Exploits são críticos
                findings.append(f"Exploits verificados pelo Metasploit: {exploit_count}")
        
        if 'exploits_executed' in metasploit_data:
            executed_count = len(metasploit_data['exploits_executed'])
            if executed_count > 0:
                risk_score += executed_count * 5  # Exploits executados são extremamente críticos
                findings.append(f"Exploits executados com sucesso: {executed_count}")
        
        # 🔥 ANÁLISE BLACK HAT EXPLOITS 🔥
        blackhat_data = target_result.get('blackhat_exploits', [])
        if isinstance(blackhat_data, list):
            critical_exploits = [e for e in blackhat_data if e.risk_level == "CRITICAL"]
            high_exploits = [e for e in blackhat_data if e.risk_level == "HIGH"]
            
            if critical_exploits:
                risk_score += len(critical_exploits) * 8  # Exploits críticos são extremamente perigosos
                findings.append(f"💀 EXPLOITS CRÍTICOS BLACK HAT: {len(critical_exploits)}")
            
            if high_exploits:
                risk_score += len(high_exploits) * 5
                findings.append(f"🔥 Exploits de alto risco encontrados: {len(high_exploits)}")
        
        # 🎭 ANÁLISE DE EVASÃO
        evasion_data = target_result.get('evasion_results', {})
        for port, evasion_results in evasion_data.items():
            if isinstance(evasion_results, list):
                successful_evasions = [e for e in evasion_results if e.success]
                if successful_evasions:
                    risk_score += len(successful_evasions) * 2
                    findings.append(f"🎭 Técnicas de evasão funcionais: {len(successful_evasions)}")
        
        # 🧠 ANÁLISE DE IA
        ai_data = target_result.get('ai_analysis', {})
        for port, ai_results in ai_data.items():
            if isinstance(ai_results, list):
                high_confidence_vulns = [a for a in ai_results if a.confidence_score > 0.8]
                if high_confidence_vulns:
                    risk_score += len(high_confidence_vulns) * 6
                    findings.append(f"🧠 Vulnerabilidades detectadas por IA: {len(high_confidence_vulns)}")
        
        # 🎯 POLYGLOT FUZZING
        fuzzing_data = target_result.get('polyglot_fuzzing', {})
        for port, fuzz_results in fuzzing_data.items():
            if isinstance(fuzz_results, list):
                confirmed_vulns = [f for f in fuzz_results if f.vulnerability_detected and f.confidence > 0.7]
                if confirmed_vulns:
                    risk_score += len(confirmed_vulns) * 4
                    findings.append(f"🎯 Vulnerabilidades confirmadas por fuzzing: {len(confirmed_vulns)}")
        
        # 🔗 LATERAL MOVEMENT
        lateral_data = target_result.get('lateral_movement', {})
        if isinstance(lateral_data, dict):
            discovered_hosts = lateral_data.get('discovered_hosts', {})
            pivot_paths = lateral_data.get('pivot_paths', [])
            
            if len(discovered_hosts) > 1:
                risk_score += len(discovered_hosts) * 3
                findings.append(f"🔗 Hosts comprometidos via pivoting: {len(discovered_hosts)}")
            
            if pivot_paths:
                risk_score += len(pivot_paths) * 2
                findings.append(f"🔗 Caminhos de pivoting disponíveis: {len(pivot_paths)}")
            
            # Credenciais encontradas
            creds_harvested = lateral_data.get('credentials_harvested', [])
            if creds_harvested:
                risk_score += len(creds_harvested) * 3
                findings.append(f"🔑 Credenciais coletadas: {len(creds_harvested)}")
        
        # 💀 AUTO-EXPLORAÇÃO
        auto_exploit_data = target_result.get('automated_exploitation', [])
        if isinstance(auto_exploit_data, list):
            successful_exploits = [e for e in auto_exploit_data if e.get('status') == 'EXPLOITED']
            if successful_exploits:
                risk_score += len(successful_exploits) * 15  # Peso máximo para exploração confirmada
                findings.append(f"💀 EXPLORAÇÃO CONFIRMADA: {len(successful_exploits)} vulnerabilidades exploradas")
        
        # 🕵️ OSINT INTELLIGENCE
        osint_data = target_result.get('osint_reconnaissance', {})
        if isinstance(osint_data, dict):
            exposed_files = osint_data.get('exposed_files', [])
            email_addresses = osint_data.get('email_addresses', [])
            sensitive_pastebins = osint_data.get('pastebins', [])
            
            if exposed_files:
                risk_score += len(exposed_files) * 2
                findings.append(f"📁 Arquivos sensíveis expostos: {len(exposed_files)}")
            
            if len(email_addresses) > 5:  # Muitos emails podem indicar vazamento
                risk_score += 3
                findings.append(f"📧 Múltiplos emails coletados: {len(email_addresses)}")
            
            if sensitive_pastebins:
                risk_score += len(sensitive_pastebins) * 5
                findings.append(f"📋 Vazamentos em pastebins: {len(sensitive_pastebins)}")
        
        # 📄 PROOF OF CONCEPTS
        poc_data = target_result.get('proof_of_concepts', [])
        if poc_data:
            risk_score += len(poc_data) * 8
            findings.append(f"📄 PoCs gerados: {len(poc_data)}")
        
        # 👻 STEALTH SUCCESS
        stealth_data = target_result.get('stealth_configuration', {})
        if stealth_data and stealth_data.get('stealth_level') == 'maximum':
            findings.append(f"👻 Scan realizado em modo stealth máximo")
        
        # Determinar nível de risco
        if risk_score >= 5:
            risk_level = "HIGH"
        elif risk_score >= 3:
            risk_level = "MEDIUM"
        elif risk_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'findings': findings
        }
    
    def generate_report(self, output_file=None):
        """Gera relatório final dos resultados"""
        self.logger.info("Gerando relatório final...")
        
        # Calcular estatísticas
        total_targets = len(self.results['targets'])
        high_risk = len([t for t in self.results['targets'] 
                        if t.get('risk_assessment', {}).get('risk_level') == 'HIGH'])
        
        self.results['summary'] = {
            'total_targets': total_targets,
            'high_risk_targets': high_risk,
            'scan_completed': datetime.now().isoformat()
        }
        
        # Salvar na pasta output/
        if output_file:
            output_dir = Path('output')
            output_dir.mkdir(exist_ok=True)
            output_path = output_dir / Path(output_file).name
            self.file_handler.save_results(self.results, str(output_path))
            self.logger.success(f"Relatório salvo em: {output_path}")
        
        # Exibir resumo na tela
        self.output_formatter.display_summary(self.results)





class CustomHelpFormatter(argparse.HelpFormatter):
    """Formatter customizado para exibir banner no help"""
    def format_help(self):
        # Exibir banner customizado
        display_help_banner()
        return ""

def main():
    """Função principal da CLI"""
    # Verificar se é solicitação de help
    if '--help' in sys.argv or '-h' in sys.argv:
        display_help_banner()
        sys.exit(0)
    
    # Exibir banner da ferramenta
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="Banner Scanner & Footprinting Tool - Revalidação de Endpoints",
        formatter_class=CustomHelpFormatter,
        add_help=False  # Desabilitar help padrão
    )
    
    # Argumentos principais
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', 
                      help='Alvo único (IP ou domínio)')
    group.add_argument('-f', '--file', 
                      help='Arquivo .txt com lista de alvos')
    
    # Argumentos opcionais
    parser.add_argument('-o', '--output', 
                       help='Arquivo de saída para resultados (JSON)')
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Modo verboso')
    parser.add_argument('--audit', 
                       action='store_true',
                       help='Modo audit (sem execução real)')
    parser.add_argument('--delay', 
                       type=int, default=1,
                       help='Delay entre scans (segundos)')
    parser.add_argument('--nuclei', 
                       choices=['quick', 'comprehensive', 'critical', 'aggressive', 'off'],
                       default='comprehensive',
                       help='Tipo de scan Nuclei (default: comprehensive)')
    parser.add_argument('--nuclei-tags', 
                       help='Tags específicas para templates Nuclei (separadas por vírgula)')
    parser.add_argument('--metasploit', 
                       choices=['off', 'verify', 'exploit', 'aggressive'],
                       default='off',
                       help='Modo Metasploit: off=desabilitado, verify=verificar exploits, exploit=executar exploits, aggressive=máxima agressividade (PERIGOSO!)')
    parser.add_argument('--metasploit-confirm', 
                       action='store_true',
                       help='Confirmar execução de exploits (obrigatório para modo exploit)')
    
    # Modos agressivos para Red Team e Bug Bounty
    parser.add_argument('--aggressive', 
                       action='store_true',
                       help='Ativa modo agressivo (Red Team/Bug Bounty) - APENAS EM AMBIENTES AUTORIZADOS')
    
    parser.add_argument('--redteam', 
                       action='store_true',
                       help='Modo Red Team - foco em exploits críticos e evasão')
    
    parser.add_argument('--bugbounty', 
                       action='store_true',
                       help='Modo Bug Bounty - foco em vulnerabilidades web e CVEs recentes')
    
    # 🔥 NOVO MODO BLACK HAT 🔥
    parser.add_argument('--blackhat', 
                       action='store_true',
                       help='🔥 MODO BLACK HAT - NÍVEL MÁXIMO DE AGRESSIVIDADE (exploits zero-day, evasão avançada, IA) - APENAS AMBIENTES AUTORIZADOS!')
    
    # 🚀 NOVOS MÓDULOS AVANÇADOS 🚀
    parser.add_argument('--auto-exploit', 
                       action='store_true',
                       help='💀 Exploração automatizada com verificação de payload')
    
    parser.add_argument('--osint', 
                       action='store_true',
                       help='🕵️ Reconhecimento OSINT completo (redes sociais, pastebins, GitHub)')
    
    parser.add_argument('--stealth-mode', 
                       choices=['normal', 'ninja', 'ghost', 'phantom'],
                       default='normal',
                       help='👻 Modo stealth para evasão de detecção')
    
    parser.add_argument('--generate-poc', 
                       action='store_true',
                       help='📄 Gerar Proof of Concept para vulnerabilidades encontradas')
    
    # 🕳️ NOVOS ARGUMENTOS EXPERT 🕳️
    parser.add_argument('--zero-day-discovery', 
                       action='store_true',
                       help='🕳️ Descoberta automática de zero-days usando análise comportamental')
    
    parser.add_argument('--c2-deployment', 
                       action='store_true',
                       help='🎯 Deploy de framework C2 para pós-exploração')
    
    parser.add_argument('--advanced-persistence', 
                       action='store_true',
                       help='🔒 Implementar técnicas avançadas de persistência')
    
    parser.add_argument('--lateral-movement-advanced', 
                       action='store_true',
                       help='🔗 Movimento lateral avançado com técnicas de AD')
    
    # 💀 ARGUMENTOS NÍVEL 10/10 💀
    parser.add_argument('--memory-corruption', 
                       action='store_true',
                       help='💀 Exploits de memory corruption (ROP chains, heap spray, JIT spray)')
    
    parser.add_argument('--kernel-exploits', 
                       action='store_true',
                       help='🔥 Exploits de kernel para privilege escalation')
    
    parser.add_argument('--advanced-payloads', 
                       action='store_true',
                       help='🎯 Geração de payloads polimórficos e anti-detecção')
    
    parser.add_argument('--absolute-expert', 
                       action='store_true',
                       help='💀💀💀 MODO ABSOLUTE EXPERT - TODOS OS MÓDULOS NÍVEL 10/10 - EXTREMAMENTE PERIGOSO!')
    
    parser.add_argument('-h', '--help', 
                       action='store_true',
                       help='Mostrar esta mensagem de ajuda')
    
    args = parser.parse_args()
    
    # Verificar se help foi solicitado
    if args.help:
        display_help_banner()
        sys.exit(0)
    
    # Configurar modos especiais
    aggressive_mode = args.aggressive
    nuclei_mode = args.nuclei
    metasploit_mode = args.metasploit
    
    if args.redteam:
        aggressive_mode = True
        nuclei_mode = 'redteam'
        metasploit_mode = 'redteam' if args.metasploit != 'off' else 'off'
    elif args.bugbounty:
        aggressive_mode = True
        nuclei_mode = 'bugbounty'
        metasploit_mode = 'bugbounty' if args.metasploit != 'off' else 'off'
    elif args.blackhat:
        # 🔥 MODO BLACK HAT - MÁXIMA AGRESSIVIDADE 🔥
        print("\n" + "="*80)
        print("🔥" * 20 + " MODO BLACK HAT ATIVADO " + "🔥" * 20)
        print("="*80)
        print("⚠️  ATENÇÃO: MODO DE MÁXIMA AGRESSIVIDADE ATIVADO!")
        print("⚠️  Este modo inclui:")
        print("    💀 Exploits zero-day (CVEs 2024)")
        print("    🎭 Técnicas avançadas de evasão WAF/IDS/IPS")
        print("    🧠 Detecção de vulnerabilidades por IA")
        print("    🔗 Auto-pivoting e lateral movement")
        print("    🎯 Payloads políglotas e fuzzing inteligente")
        print("⚠️  USE APENAS EM AMBIENTES AUTORIZADOS!")
        print("="*80 + "\n")
        
        aggressive_mode = True
        nuclei_mode = 'aggressive'
        metasploit_mode = 'aggressive' if args.metasploit != 'off' else 'verify'
    
    # 🚀 PROCESSAR NOVOS ARGUMENTOS AVANÇADOS 🚀
    # Verificar argumentos dos novos módulos
    auto_exploit_mode = getattr(args, 'auto_exploit', False)
    osint_mode = getattr(args, 'osint', False)
    stealth_mode = getattr(args, 'stealth_mode', 'normal')
    generate_poc = getattr(args, 'generate_poc', False)
    
    # 🕳️ NOVOS MÓDULOS EXPERT 🕳️
    zero_day_discovery_mode = getattr(args, 'zero_day_discovery', False)
    c2_deployment_mode = getattr(args, 'c2_deployment', False)
    persistence_mode = getattr(args, 'advanced_persistence', False)
    lateral_movement_advanced = getattr(args, 'lateral_movement_advanced', False)
    
    # 💀 MÓDULOS NÍVEL 10/10 💀
    memory_corruption_mode = getattr(args, 'memory_corruption', False)
    kernel_exploits_mode = getattr(args, 'kernel_exploits', False)
    advanced_payloads_mode = getattr(args, 'advanced_payloads', False)
    absolute_expert_mode = getattr(args, 'absolute_expert', False)
    
    # MODO ABSOLUTE EXPERT ativa tudo
    if absolute_expert_mode:
        print(f"\n{'='*80}")
        print(f"{'='*25} ABSOLUTE EXPERT MODE ACTIVATED {'='*25}")
        print(f"{'='*80}")
        print("🎯 MAXIMUM AGGRESSION LEVEL - ALL TECHNIQUES ENABLED")
        print("\n📋 ACTIVATED MODULES:")
        print("   🕳️  Zero-day Discovery Engine")
        print("   🎯 C2 Framework Deployment")
        print("   🔒 Advanced Persistence (Rootkits/Bootkits)")
        print("   🔗 Advanced Lateral Movement")
        print("   💀 Memory Corruption Exploits")
        print("   🔥 Kernel Privilege Escalation")
        print("   🎯 Polymorphic Payload Generation")
        print("   👻 Phantom Stealth Mode")
        print("\n⚠️  WARNING: USE ONLY IN AUTHORIZED ENVIRONMENTS!")
        print(f"{'='*80}\n")
        
        # Ativar todos os módulos
        aggressive_mode = True
        nuclei_mode = 'aggressive'
        metasploit_mode = 'aggressive'
        auto_exploit_mode = True
        osint_mode = True
        stealth_mode = 'phantom'
        generate_poc = True
        zero_day_discovery_mode = True
        c2_deployment_mode = True
        persistence_mode = True
        lateral_movement_advanced = True
        memory_corruption_mode = True
        kernel_exploits_mode = True
        advanced_payloads_mode = True
    
    # Mostrar avisos apenas se não for modo absolute expert (para evitar spam)
    if not absolute_expert_mode:
        active_modules = []
        
        if auto_exploit_mode and not args.audit:
            active_modules.append("💀 Auto-Exploitation Mode")
        if osint_mode:
            active_modules.append("🕵️ OSINT Reconnaissance")
        if stealth_mode != 'normal':
            active_modules.append(f"👻 Stealth Mode: {stealth_mode.title()}")
        if generate_poc:
            active_modules.append("📄 PoC Generation")
        if zero_day_discovery_mode and not args.audit:
            active_modules.append("🕳️ Zero-day Discovery")
        if c2_deployment_mode and not args.audit:
            active_modules.append("🎯 C2 Framework")
        if persistence_mode and not args.audit:
            active_modules.append("🔒 Advanced Persistence")
        if lateral_movement_advanced:
            active_modules.append("🔗 Advanced Lateral Movement")
        if memory_corruption_mode and not args.audit:
            active_modules.append("💀 Memory Corruption Exploits")
        if kernel_exploits_mode and not args.audit:
            active_modules.append("🔥 Kernel Exploits")
        if advanced_payloads_mode:
            active_modules.append("🎯 Polymorphic Payloads")
        
        if active_modules:
            print(f"\n{'─'*60}")
            print("🚀 ACTIVE MODULES:")
            for module in active_modules:
                print(f"   {module}")
            print(f"{'─'*60}\n")
    
    # Aviso especial para absolute expert
    if absolute_expert_mode and not args.audit:
        print("⚠️  ABSOLUTE EXPERT MODE - MAXIMUM RESPONSIBILITY REQUIRED!")
        print("🎯 ALL ATTACK VECTORS ACTIVATED - USE WITH EXTREME CAUTION!\n")
    
    # Verificar dependências
    if not check_dependencies():
        sys.exit(1)
    
    # Inicializar ferramenta
    scanner = BannerScanTool(
        verbose=args.verbose, 
        audit_mode=args.audit,
        nuclei_mode=nuclei_mode,
        nuclei_tags=args.nuclei_tags,
        metasploit_mode=metasploit_mode,
        metasploit_confirm=args.metasploit_confirm,
        aggressive_mode=aggressive_mode
    )
    
    # Configurar novos módulos
    scanner.auto_exploit_mode = auto_exploit_mode
    scanner.osint_mode = osint_mode
    scanner.stealth_mode = stealth_mode
    scanner.generate_poc_mode = generate_poc
    
    # 🕳️ CONFIGURAR NOVOS MÓDULOS EXPERT 🕳️
    scanner.zero_day_discovery_mode = zero_day_discovery_mode
    scanner.c2_deployment_mode = c2_deployment_mode
    scanner.persistence_mode = persistence_mode
    scanner.lateral_movement_advanced = lateral_movement_advanced
    
    # 💀 CONFIGURAR MÓDULOS NÍVEL 10/10 💀
    scanner.memory_corruption_mode = memory_corruption_mode
    scanner.kernel_exploits_mode = kernel_exploits_mode
    scanner.advanced_payloads_mode = advanced_payloads_mode
    scanner.absolute_expert_mode = absolute_expert_mode
    
    try:
        # Executar scan
        if args.target:
            scanner.scan_single_target(args.target)
        elif args.file:
            if not os.path.exists(args.file):
                print(f"Erro: Arquivo não encontrado: {args.file}")
                sys.exit(1)
            scanner.scan_from_file(args.file)
        
        # Gerar relatório
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erro fatal: {str(e)}")
        sys.exit(1)

def check_dependencies():
    """Verifica se as dependências estão instaladas"""
    dependencies = ['nmap', 'whois']
    missing = []
    
    for dep in dependencies:
        if os.system(f"which {dep} > /dev/null 2>&1") != 0:
            missing.append(dep)
    
    if missing:
        print(f"[!] Dependências não encontradas: {', '.join(missing)}")
        print("[*] Instale com: sudo apt-get install nmap whois")
        return False
    
    return True

if __name__ == "__main__":
    main()
