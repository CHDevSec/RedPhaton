# Comandos para Red Team e Bug Bounty

## 🔴 ATENÇÃO: Use apenas em ambientes autorizados!

Este documento contém comandos para uso em exercícios de Red Team e programas de Bug Bounty autorizados.

## Modos Disponíveis

### 1. Modo Agressivo Geral
```bash
# Scan agressivo completo
python ScanBanner.py -t target.com --aggressive --metasploit verify -o relatorio_agressivo.html

# Scan agressivo com Nuclei e Metasploit
python ScanBanner.py -t target.com --aggressive --metasploit aggressive -o scan_completo.html
```

### 2. Modo Red Team
```bash
# Red Team - foco em exploits críticos
python ScanBanner.py -t target.com --redteam --metasploit redteam -o redteam_report.html

# Red Team com lista de alvos
python ScanBanner.py -f targets.txt --redteam --metasploit redteam -o redteam_multiple.html

# Red Team com delay para evasão
python ScanBanner.py -t target.com --redteam --delay 5 -o redteam_stealth.html
```

### 3. Modo Bug Bounty
```bash
# Bug Bounty - foco em vulnerabilidades web
python ScanBanner.py -t target.com --bugbounty --metasploit bugbounty -o bugbounty_report.html

# Bug Bounty com tags específicas do Nuclei
python ScanBanner.py -t target.com --bugbounty --nuclei-tags "xss,sqli,ssrf" -o web_vulns.html

# Bug Bounty em múltiplos subdomínios
python ScanBanner.py -f subdomains.txt --bugbounty -o bounty_scan.html
```

## Comandos por Tipo de Vulnerabilidade

### Exploits Críticos (Red Team)
```bash
# Foco em RCE e deserialização
python ScanBanner.py -t target.com --nuclei critical --nuclei-tags "rce,deserialization" --metasploit redteam

# Scan de SMB e Windows
python ScanBanner.py -t windows-target.com --redteam --metasploit aggressive

# Verificação de CVEs críticos
python ScanBanner.py -t target.com --nuclei redteam --nuclei-tags "cve,log4j,spring"
```

### Vulnerabilidades Web (Bug Bounty)
```bash
# XSS e Injection
python ScanBanner.py -t webapp.com --bugbounty --nuclei-tags "xss,sqli,ssti,xxe"

# SSRF e LFI/RFI
python ScanBanner.py -t api.target.com --bugbounty --nuclei-tags "ssrf,lfi,rfi"

# Subdomain Takeover
python ScanBanner.py -f subdomains.txt --nuclei bugbounty --nuclei-tags "takeover,dns"
```

## Configurações Avançadas

### Scan Stealth (Evasão)
```bash
# Scan lento para evasão de IDS
python ScanBanner.py -t target.com --redteam --delay 10 --metasploit verify

# Modo audit para teste sem execução real
python ScanBanner.py -t target.com --audit --redteam
```

### Scan Intensivo
```bash
# Máxima agressividade (cuidado!)
python ScanBanner.py -t target.com --aggressive --nuclei aggressive --metasploit aggressive

# Scan completo com todas as tags
python ScanBanner.py -t target.com --nuclei comprehensive --metasploit aggressive
```

## Tipos de Relatório

### Relatórios Especializados
```bash
# Relatório focado em Red Team
python ScanBanner.py -t target.com --redteam -o redteam_$(date +%Y%m%d).html

# Relatório para Bug Bounty
python ScanBanner.py -t target.com --bugbounty -o bounty_$(date +%Y%m%d).html

# Relatório JSON para automação
python ScanBanner.py -t target.com --aggressive -o results.json
```

## Exemplos de Uso por Cenário

### Pentest Interno
```bash
# Rede interna - modo agressivo
python ScanBanner.py -f internal_ips.txt --aggressive --metasploit aggressive

# Scan de Active Directory
python ScanBanner.py -t dc.internal.com --redteam --nuclei-tags "smb,ldap,kerberos"
```

### Bug Bounty Web
```bash
# Aplicação web principal
python ScanBanner.py -t app.target.com --bugbounty --nuclei-tags "web,api,cms"

# APIs e microserviços
python ScanBanner.py -f api_endpoints.txt --bugbounty --nuclei-tags "api,graphql,rest"
```

### Red Team Exercise
```bash
# Reconhecimento inicial
python ScanBanner.py -t target.com --redteam --metasploit verify

# Exploração ativa (com confirmação)
python ScanBanner.py -t target.com --redteam --metasploit exploit --metasploit-confirm
```

## Novas Funcionalidades

### Nuclei Melhorado
- **Modo Agressivo**: Mais templates, maior concorrência
- **Modo Red Team**: Foco em RCE, bypass, takeover
- **Modo Bug Bounty**: Vulnerabilidades web, CVEs recentes

### Metasploit Expandido
- **60+ módulos auxiliares** para enumeração
- **50+ exploits verificáveis** incluindo CVEs recentes
- **Brute force** em serviços comuns
- **Enumeração avançada** para Red Team

### Detecções Aprimoradas
- **CVEs 2021-2024** incluindo Log4Shell, Spring4Shell
- **Vulnerabilidades de CMS** (WordPress, Joomla, Drupal)
- **Exploits de IoT** e dispositivos de rede
- **Técnicas de evasão** e bypass

## ⚠️ Avisos Importantes

1. **Use apenas em ambientes autorizados**
2. **Respeite o scope dos programas de bug bounty**
3. **Configure delays apropriados para evitar DoS**
4. **Monitore logs para detectar bloqueios**
5. **Mantenha templates do Nuclei atualizados**

## Troubleshooting

```bash
# Verificar se Nuclei está atualizado
nuclei -update-templates

# Verificar versão do Metasploit
msfconsole --version

# Teste em modo audit primeiro
python ScanBanner.py -t target.com --audit --redteam
```