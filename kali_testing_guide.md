# Guia de Teste Completo - Kali Linux

## 🐉 Preparação do Ambiente Kali

### 1. Atualizar o Sistema
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Instalar Dependências
```bash
# Python e pip
sudo apt install python3 python3-pip -y

# Nmap (geralmente já vem instalado)
sudo apt install nmap -y

# Whois
sudo apt install whois -y

# Go (para Nuclei)
sudo apt install golang-go -y

# Metasploit (geralmente já vem instalado)
sudo apt install metasploit-framework -y
```

### 3. Instalar Nuclei
```bash
# Instalar Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Adicionar Go bin ao PATH (adicionar ao ~/.bashrc)
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verificar instalação
nuclei -version

# Atualizar templates
nuclei -update-templates
```

### 4. Instalar Dependências Python
```bash
cd /caminho/para/Banner_fingerprint
pip3 install -r requirements.txt
```

## 🚀 Testes Completos

### Teste 1: Scan Básico (Nmap + Banners)
```bash
# Teste simples
python3 ScanBanner.py -t scanme.nmap.org -v

# Com saída JSON
python3 ScanBanner.py -t scanme.nmap.org -o teste_basico.json -v
```

### Teste 2: Scan com Nuclei
```bash
# Scan rápido com Nuclei
python3 ScanBanner.py -t scanme.nmap.org --nuclei quick -v

# Scan completo com Nuclei
python3 ScanBanner.py -t scanme.nmap.org --nuclei comprehensive -o teste_nuclei.json -v

# Scan com tags específicas
python3 ScanBanner.py -t scanme.nmap.org --nuclei comprehensive --nuclei-tags cve,rce -v
```

### Teste 3: Scan com Metasploit (Modo Verify)
```bash
# Verificação de exploits (SEGURO)
python3 ScanBanner.py -t scanme.nmap.org --metasploit verify -v

# Combinado: Nmap + Nuclei + Metasploit
python3 ScanBanner.py -t scanme.nmap.org --nuclei comprehensive --metasploit verify -o teste_completo.json -v
```

### Teste 4: Scan Completo com Relatório HTML
```bash
# Scan completo com todas as funcionalidades
python3 ScanBanner.py -t scanme.nmap.org \
  --nuclei comprehensive \
  --metasploit verify \
  -o relatorio_completo.html \
  -v
```

### Teste 5: Múltiplos Alvos
```bash
# Criar arquivo de alvos
echo -e "scanme.nmap.org\ntestphp.vulnweb.com\nhackthissite.org" > alvos_teste.txt

# Scan de múltiplos alvos
python3 ScanBanner.py -f alvos_teste.txt \
  --nuclei quick \
  --metasploit verify \
  --delay 2 \
  -o scan_multiplos.json \
  -v
```

### Teste 6: Modo Audit (Simulação)
```bash
# Teste sem execução real (para documentação)
python3 ScanBanner.py -t target.com \
  --audit \
  --nuclei comprehensive \
  --metasploit exploit \
  --metasploit-confirm \
  -v
```

## 🎯 Alvos de Teste Seguros

### Alvos Públicos para Teste
```bash
# Alvos oficiais para teste
scanme.nmap.org          # Oficial do Nmap
testphp.vulnweb.com      # Aplicação web vulnerável
hackthissite.org         # Site de desafios
testfire.net             # Aplicação bancária de teste
```

### Laboratórios Locais
```bash
# DVWA (Damn Vulnerable Web Application)
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Metasploitable2
# Baixar VM do Metasploitable2 e testar localmente
```

## 📊 Verificação de Relatórios

### Estrutura de Saída JSON
```bash
# Visualizar relatório JSON
cat teste_completo.json | jq .

# Extrair apenas vulnerabilidades
cat teste_completo.json | jq '.results[].nuclei_scan.vulnerabilities'

# Extrair exploits encontrados
cat teste_completo.json | jq '.results[].metasploit_scan.exploits_found'
```

### Relatório HTML
```bash
# Abrir relatório HTML no navegador
firefox relatorio_completo.html &

# Ou usar servidor HTTP simples
python3 -m http.server 8000
# Acessar: http://localhost:8000/relatorio_completo.html
```

## 🔍 Troubleshooting

### Verificar Instalações
```bash
# Verificar todas as dependências
nmap --version
nuclei -version
msfconsole -v
python3 --version
whois --version
```

### Problemas Comuns

#### Nuclei não encontrado
```bash
# Verificar PATH
echo $PATH
which nuclei

# Reinstalar se necessário
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

#### Metasploit não inicia
```bash
# Inicializar database
sudo msfdb init

# Testar console
msfconsole -q -x "version; exit"
```

#### Permissões
```bash
# Alguns scans podem precisar de root
sudo python3 ScanBanner.py -t target.com --metasploit verify -v
```

## 🛡️ Testes de Segurança

### Teste 1: Verificar Modo OFF
```bash
# Metasploit deve estar desabilitado por padrão
python3 ScanBanner.py -t scanme.nmap.org -v
# Verificar que não há seção metasploit_scan no resultado
```

### Teste 2: Verificar Confirmação Obrigatória
```bash
# Sem --metasploit-confirm deve virar modo verify
python3 ScanBanner.py -t scanme.nmap.org --metasploit exploit -v
# Verificar logs: "Modo exploit requer confirmação explícita - usando modo verify"
```

### Teste 3: Modo Audit
```bash
# Modo audit não deve executar comandos reais
python3 ScanBanner.py -t scanme.nmap.org --audit --metasploit exploit --metasploit-confirm -v
# Verificar logs: "[AUDIT] Simulando..."
```

## 📋 Checklist de Teste

- [ ] ✅ Scan básico funciona
- [ ] ✅ Nuclei encontra vulnerabilidades
- [ ] ✅ Metasploit modo verify funciona
- [ ] ✅ Relatórios JSON são gerados
- [ ] ✅ Relatórios HTML são gerados
- [ ] ✅ Múltiplos alvos funcionam
- [ ] ✅ Modo audit simula corretamente
- [ ] ✅ Medidas de segurança ativas
- [ ] ✅ Logs detalhados funcionam
- [ ] ✅ Avaliação de risco inclui todos os componentes

## 🎉 Exemplo de Comando Completo

```bash
# Comando final para teste completo
python3 ScanBanner.py -t scanme.nmap.org \
  --nuclei comprehensive \
  --nuclei-tags cve,rce,sqli \
  --metasploit verify \
  --delay 1 \
  -o relatorio_final.json \
  -v

# Verificar resultado
echo "=== RESUMO DO SCAN ==="
cat relatorio_final.json | jq '.summary'
echo "\n=== RISCOS ENCONTRADOS ==="
cat relatorio_final.json | jq '.results[].risk_assessment'
```

## 📞 Suporte

Se encontrar problemas:
1. Verificar logs detalhados com `-v`
2. Testar componentes individualmente
3. Usar modo `--audit` para debug
4. Verificar permissões e dependências

**Lembre-se**: Sempre teste em ambientes autorizados! 🔒