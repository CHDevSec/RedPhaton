# Comandos Rápidos - Banner Scanner

## 🚀 Comandos Essenciais

### Preparação (Kali Linux)
```bash
# Tornar scripts executáveis
chmod +x demo_completo.sh
chmod +x test_integration.py

# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependências
sudo apt install python3 python3-pip nmap whois metasploit-framework golang-go jq -y

# Instalar Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Atualizar templates Nuclei
nuclei -update-templates

# Instalar dependências Python
pip3 install -r requirements.txt
```

## 🎯 Testes Rápidos

### 1. Teste de Integração Automatizado
```bash
# Executar todos os testes automaticamente
python3 test_integration.py

# Ver ajuda do teste
python3 test_integration.py --help
```

### 2. Demo Completo
```bash
# Executar demonstração completa
./demo_completo.sh

# Ou se não for executável:
bash demo_completo.sh
```

### 3. Testes Manuais Rápidos

#### Scan Básico
```bash
python3 ScanBanner.py -t scanme.nmap.org -v
```

#### Scan com Nuclei
```bash
python3 ScanBanner.py -t scanme.nmap.org --nuclei quick -v
```

#### Scan com Metasploit (Seguro)
```bash
python3 ScanBanner.py -t scanme.nmap.org --metasploit verify -v
```

#### Scan Completo
```bash
python3 ScanBanner.py -t scanme.nmap.org \
  --nuclei comprehensive \
  --metasploit verify \
  -o resultado_completo.json \
  -v
```

#### Múltiplos Alvos
```bash
# Criar arquivo de alvos
echo -e "scanme.nmap.org\ntestphp.vulnweb.com" > alvos.txt

# Executar scan
python3 ScanBanner.py -f alvos.txt \
  --nuclei quick \
  --metasploit verify \
  --delay 2 \
  -o multiplos_alvos.json \
  -v
```

## 📊 Análise de Resultados

### Visualizar JSON
```bash
# Instalar jq se não tiver
sudo apt install jq -y

# Ver resultado completo
cat resultado_completo.json | jq .

# Ver apenas resumo
cat resultado_completo.json | jq '.summary'

# Ver riscos encontrados
cat resultado_completo.json | jq '.results[].risk_assessment'

# Ver vulnerabilidades Nuclei
cat resultado_completo.json | jq '.results[].nuclei_scan.vulnerabilities'

# Ver exploits Metasploit
cat resultado_completo.json | jq '.results[].metasploit_scan.exploits_found'

# Ver portas abertas
cat resultado_completo.json | jq '.results[].nmap_scan.open_ports'
```

### Relatórios HTML
```bash
# Gerar relatório HTML
python3 ScanBanner.py -t scanme.nmap.org \
  --nuclei quick \
  --metasploit verify \
  -o relatorio.html \
  -v

# Abrir no navegador
firefox relatorio.html &
# ou
google-chrome relatorio.html &
```

## 🛡️ Testes de Segurança

### Verificar Modo OFF (Padrão)
```bash
# Metasploit deve estar desabilitado
python3 ScanBanner.py -t scanme.nmap.org -o teste_off.json -v
cat teste_off.json | jq '.results[].metasploit_scan'
# Deve mostrar: {"disabled": true}
```

### Verificar Rebaixamento de Exploit
```bash
# Sem --metasploit-confirm deve virar verify
python3 ScanBanner.py -t scanme.nmap.org --metasploit exploit -v
# Deve mostrar: "usando modo verify" nos logs
```

### Modo Audit
```bash
# Simular sem executar comandos reais
python3 ScanBanner.py -t scanme.nmap.org \
  --audit \
  --metasploit exploit \
  --metasploit-confirm \
  -v
# Deve mostrar: "[AUDIT] Simulando..." nos logs
```

## 🎯 Alvos de Teste Seguros

```bash
# Alvos oficiais para teste
scanme.nmap.org          # Oficial do Nmap
testphp.vulnweb.com      # App web vulnerável
hackthissite.org         # Desafios de segurança
testfire.net             # App bancária de teste
```

## 🔧 Troubleshooting

### Verificar Dependências
```bash
# Verificar versões
python3 --version
nmap --version
nuclei -version
msfconsole -v
whois --version
```

### Problemas Comuns

#### Nuclei não encontrado
```bash
# Verificar PATH
echo $PATH
which nuclei

# Reinstalar
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

#### Metasploit não inicia
```bash
# Inicializar database
sudo msfdb init

# Testar
msfconsole -q -x "version; exit"
```

#### Permissões
```bash
# Alguns scans precisam de root
sudo python3 ScanBanner.py -t target.com --metasploit verify -v
```

## 📋 Checklist de Teste

- [ ] ✅ Python3 instalado e funcionando
- [ ] ✅ Nmap instalado e funcionando
- [ ] ✅ Nuclei instalado e templates atualizados
- [ ] ✅ Metasploit instalado e database inicializada
- [ ] ✅ Dependências Python instaladas
- [ ] ✅ Scan básico funciona
- [ ] ✅ Nuclei encontra vulnerabilidades
- [ ] ✅ Metasploit modo verify funciona
- [ ] ✅ Relatórios JSON são gerados
- [ ] ✅ Relatórios HTML são gerados
- [ ] ✅ Múltiplos alvos funcionam
- [ ] ✅ Modo audit simula corretamente
- [ ] ✅ Medidas de segurança ativas

## 🚨 Comandos de Emergência

### Parar Todos os Processos
```bash
# Parar processos Python
pkill -f "python.*ScanBanner"

# Parar Nuclei
pkill nuclei

# Parar Metasploit
pkill msfconsole
```

### Limpar Arquivos de Teste
```bash
# Remover arquivos de teste
rm -f test_*.json demo_*.json resultado_*.json multiplos_*.json
rm -f *.html
rm -rf demo_results_*
```

## 📞 Suporte

Se encontrar problemas:
1. ✅ Verificar logs com `-v`
2. ✅ Testar componentes individualmente
3. ✅ Usar modo `--audit` para debug
4. ✅ Verificar permissões e dependências
5. ✅ Consultar `metasploit_examples.md`
6. ✅ Executar `test_integration.py`

**Lembre-se**: Sempre teste em ambientes autorizados! 🔒