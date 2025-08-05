# Exemplos de Uso do Metasploit

## ⚠️ AVISO IMPORTANTE

O Metasploit é uma ferramenta poderosa que pode executar exploits reais. **NUNCA** use em sistemas que não são seus ou sem autorização explícita por escrito.

## Modos de Operação

### 1. Modo OFF (Padrão)
```bash
# Metasploit desabilitado (comportamento padrão)
python3 ScanBanner.py -t target.com
python3 ScanBanner.py -t target.com --metasploit off
```

### 2. Modo VERIFY (Seguro)
```bash
# Apenas verifica se exploits existem para as vulnerabilidades encontradas
# NÃO executa os exploits
python3 ScanBanner.py -t target.com --metasploit verify

# Com verbose para ver detalhes
python3 ScanBanner.py -t target.com --metasploit verify -v

# Combinado com Nuclei
python3 ScanBanner.py -t target.com --nuclei comprehensive --metasploit verify
```

### 3. Modo EXPLOIT (Perigoso)
```bash
# ATENÇÃO: Executa exploits reais!
# Requer confirmação explícita com --metasploit-confirm
python3 ScanBanner.py -t target.com --metasploit exploit --metasploit-confirm

# Sem a flag --metasploit-confirm, será automaticamente rebaixado para modo verify
python3 ScanBanner.py -t target.com --metasploit exploit  # Será executado como 'verify'
```

## Cenários de Uso

### Pentest Autorizado
```bash
# 1. Primeiro, fazer reconhecimento
python3 ScanBanner.py -t target-autorizado.com --nuclei comprehensive

# 2. Verificar exploits disponíveis
python3 ScanBanner.py -t target-autorizado.com --metasploit verify

# 3. Se autorizado, executar exploits específicos
python3 ScanBanner.py -t target-autorizado.com --metasploit exploit --metasploit-confirm
```

### Auditoria de Segurança
```bash
# Modo audit para documentação sem execução real
python3 ScanBanner.py -t sistema-interno.com --audit --metasploit verify -v
```

### Bug Bounty
```bash
# Apenas verificação (nunca executar exploits em bug bounty!)
python3 ScanBanner.py -t target.com --nuclei comprehensive --metasploit verify
```

## Medidas de Segurança Implementadas

1. **Modo OFF por padrão**: Metasploit desabilitado por padrão
2. **Confirmação obrigatória**: Modo exploit requer flag `--metasploit-confirm`
3. **Rebaixamento automático**: Sem confirmação, exploit vira verify
4. **Modo audit**: Simula execução sem comandos reais
5. **Logs detalhados**: Todas as ações são registradas
6. **Verificação de disponibilidade**: Checa se Metasploit está instalado

## Estrutura de Saída

### Modo Verify
```json
{
  "metasploit_scan": {
    "mode": "verify",
    "exploits_found": [
      {
        "name": "exploit/linux/ssh/ssh_login",
        "description": "SSH Login Scanner",
        "rank": "manual",
        "target_port": 22
      }
    ],
    "total_exploits": 1
  }
}
```

### Modo Exploit
```json
{
  "metasploit_scan": {
    "mode": "exploit",
    "exploits_found": [...],
    "exploits_executed": [
      {
        "name": "exploit/linux/ssh/ssh_login",
        "status": "success",
        "session_id": "1",
        "timestamp": "2024-01-15T10:30:00Z"
      }
    ],
    "total_executed": 1
  }
}
```

## Considerações Legais

- ✅ **Permitido**: Sistemas próprios, laboratórios, ambientes de teste
- ✅ **Permitido**: Pentests com contrato e autorização por escrito
- ✅ **Permitido**: Bug bounty programs (apenas modo verify)
- ❌ **PROIBIDO**: Sistemas de terceiros sem autorização
- ❌ **PROIBIDO**: Redes corporativas sem permissão
- ❌ **PROIBIDO**: Qualquer uso malicioso

## Troubleshooting

### Metasploit não encontrado
```bash
# Verificar instalação
msfconsole -v

# Instalar se necessário (Ubuntu/Debian)
sudo apt-get install metasploit-framework
```

### Permissões insuficientes
```bash
# Alguns exploits podem precisar de privilégios elevados
sudo python3 ScanBanner.py -t target.com --metasploit verify
```

### Modo audit
```bash
# Para testar sem executar comandos reais
python3 ScanBanner.py -t target.com --audit --metasploit exploit --metasploit-confirm -v
```