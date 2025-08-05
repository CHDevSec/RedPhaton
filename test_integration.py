#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Teste de Integração - Banner Scanner
Testa todos os componentes: Nmap, Nuclei, Metasploit
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path

class IntegrationTester:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.scanner_path = self.base_dir / "ScanBanner.py"
        self.test_results = []
        
    def log(self, message, level="INFO"):
        """Log com timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def run_command(self, cmd, timeout=300):
        """Executa comando e retorna resultado"""
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd=self.base_dir
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Timeout expired"
        except Exception as e:
            return False, "", str(e)
            
    def check_dependencies(self):
        """Verifica se todas as dependências estão instaladas"""
        self.log("Verificando dependências...")
        
        deps = {
            "python3": "python3 --version",
            "nmap": "nmap --version",
            "nuclei": "nuclei -version",
            "metasploit": "msfconsole -v",
            "whois": "whois --version"
        }
        
        missing = []
        for name, cmd in deps.items():
            success, stdout, stderr = self.run_command(cmd)
            if success:
                self.log(f"✅ {name} encontrado")
            else:
                self.log(f"❌ {name} NÃO encontrado", "ERROR")
                missing.append(name)
                
        return len(missing) == 0, missing
        
    def test_basic_scan(self):
        """Teste 1: Scan básico"""
        self.log("\n=== TESTE 1: Scan Básico ===")
        
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org -o test_basic.json"
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists("test_basic.json"):
            self.log("✅ Scan básico funcionou")
            return True
        else:
            self.log(f"❌ Scan básico falhou: {stderr}", "ERROR")
            return False
            
    def test_nuclei_scan(self):
        """Teste 2: Scan com Nuclei"""
        self.log("\n=== TESTE 2: Scan com Nuclei ===")
        
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org --nuclei quick -o test_nuclei.json"
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists("test_nuclei.json"):
            # Verificar se há seção nuclei no resultado
            try:
                with open("test_nuclei.json", "r") as f:
                    data = json.load(f)
                    if "nuclei_scan" in str(data):
                        self.log("✅ Scan Nuclei funcionou")
                        return True
            except:
                pass
                
        self.log(f"❌ Scan Nuclei falhou: {stderr}", "ERROR")
        return False
        
    def test_metasploit_verify(self):
        """Teste 3: Metasploit modo verify"""
        self.log("\n=== TESTE 3: Metasploit Verify ===")
        
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org --metasploit verify -o test_metasploit.json"
        success, stdout, stderr = self.run_command(cmd)
        
        if success and os.path.exists("test_metasploit.json"):
            try:
                with open("test_metasploit.json", "r") as f:
                    data = json.load(f)
                    if "metasploit_scan" in str(data):
                        self.log("✅ Metasploit verify funcionou")
                        return True
            except:
                pass
                
        self.log(f"❌ Metasploit verify falhou: {stderr}", "ERROR")
        return False
        
    def test_complete_scan(self):
        """Teste 4: Scan completo"""
        self.log("\n=== TESTE 4: Scan Completo ===")
        
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org --nuclei quick --metasploit verify -o test_complete.json -v"
        success, stdout, stderr = self.run_command(cmd, timeout=600)  # 10 minutos
        
        if success and os.path.exists("test_complete.json"):
            try:
                with open("test_complete.json", "r") as f:
                    data = json.load(f)
                    has_nmap = "nmap_scan" in str(data)
                    has_nuclei = "nuclei_scan" in str(data)
                    has_metasploit = "metasploit_scan" in str(data)
                    has_risk = "risk_assessment" in str(data)
                    
                    if all([has_nmap, has_nuclei, has_metasploit, has_risk]):
                        self.log("✅ Scan completo funcionou")
                        return True
            except:
                pass
                
        self.log(f"❌ Scan completo falhou: {stderr}", "ERROR")
        return False
        
    def test_security_measures(self):
        """Teste 5: Medidas de segurança"""
        self.log("\n=== TESTE 5: Medidas de Segurança ===")
        
        # Teste 1: Metasploit OFF por padrão
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org -o test_security1.json"
        success, stdout, stderr = self.run_command(cmd)
        
        if success:
            try:
                with open("test_security1.json", "r") as f:
                    data = json.load(f)
                    # Deve ter metasploit_scan com disabled: true
                    if "disabled" in str(data) and "metasploit" in str(data):
                        self.log("✅ Metasploit OFF por padrão")
                    else:
                        self.log("❌ Metasploit não está OFF por padrão", "ERROR")
                        return False
            except:
                self.log("❌ Erro ao verificar modo OFF", "ERROR")
                return False
        
        # Teste 2: Exploit sem confirmação vira verify
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org --metasploit exploit -o test_security2.json"
        success, stdout, stderr = self.run_command(cmd)
        
        if success:
            # Verificar logs para mensagem de rebaixamento
            if "usando modo verify" in stdout or "usando modo verify" in stderr:
                self.log("✅ Exploit sem confirmação rebaixado para verify")
                return True
            else:
                self.log("❌ Exploit sem confirmação não foi rebaixado", "ERROR")
                return False
                
        return False
        
    def test_audit_mode(self):
        """Teste 6: Modo audit"""
        self.log("\n=== TESTE 6: Modo Audit ===")
        
        cmd = f"python3 {self.scanner_path} -t scanme.nmap.org --audit --metasploit exploit --metasploit-confirm -o test_audit.json -v"
        success, stdout, stderr = self.run_command(cmd)
        
        if success:
            # Verificar se há mensagens de audit nos logs
            if "[AUDIT]" in stdout or "audit_mode" in stdout:
                self.log("✅ Modo audit funcionou")
                return True
            else:
                self.log("❌ Modo audit não funcionou", "ERROR")
                return False
                
        self.log(f"❌ Modo audit falhou: {stderr}", "ERROR")
        return False
        
    def cleanup(self):
        """Limpar arquivos de teste"""
        test_files = [
            "test_basic.json",
            "test_nuclei.json", 
            "test_metasploit.json",
            "test_complete.json",
            "test_security1.json",
            "test_security2.json",
            "test_audit.json"
        ]
        
        for file in test_files:
            if os.path.exists(file):
                os.remove(file)
                
    def run_all_tests(self):
        """Executa todos os testes"""
        self.log("🚀 INICIANDO TESTES DE INTEGRAÇÃO")
        self.log("=" * 50)
        
        # Verificar dependências
        deps_ok, missing = self.check_dependencies()
        if not deps_ok:
            self.log(f"❌ Dependências faltando: {missing}", "ERROR")
            self.log("Instale as dependências antes de continuar")
            return False
            
        # Lista de testes
        tests = [
            ("Scan Básico", self.test_basic_scan),
            ("Nuclei Scan", self.test_nuclei_scan),
            ("Metasploit Verify", self.test_metasploit_verify),
            ("Scan Completo", self.test_complete_scan),
            ("Medidas de Segurança", self.test_security_measures),
            ("Modo Audit", self.test_audit_mode)
        ]
        
        results = []
        for test_name, test_func in tests:
            try:
                result = test_func()
                results.append((test_name, result))
            except Exception as e:
                self.log(f"❌ Erro no teste {test_name}: {e}", "ERROR")
                results.append((test_name, False))
                
        # Resumo
        self.log("\n" + "=" * 50)
        self.log("📊 RESUMO DOS TESTES")
        self.log("=" * 50)
        
        passed = 0
        for test_name, result in results:
            status = "✅ PASSOU" if result else "❌ FALHOU"
            self.log(f"{test_name}: {status}")
            if result:
                passed += 1
                
        total = len(results)
        self.log(f"\n🎯 RESULTADO FINAL: {passed}/{total} testes passaram")
        
        if passed == total:
            self.log("🎉 TODOS OS TESTES PASSARAM! Integração funcionando perfeitamente.")
        else:
            self.log(f"⚠️  {total - passed} teste(s) falharam. Verifique os logs acima.")
            
        # Cleanup
        self.cleanup()
        
        return passed == total

def main():
    """Função principal"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("""Script de Teste de Integração - Banner Scanner
        
Uso:
    python3 test_integration.py          # Executar todos os testes
    python3 test_integration.py --help   # Mostrar esta ajuda
    
Este script testa:
- Scan básico (Nmap + Banners)
- Integração com Nuclei
- Integração com Metasploit
- Medidas de segurança
- Modo audit
- Geração de relatórios

Certifique-se de que todas as dependências estão instaladas:
- python3, nmap, nuclei, metasploit-framework, whois
        """)
        return
        
    tester = IntegrationTester()
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()