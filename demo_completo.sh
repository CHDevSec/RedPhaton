#!/bin/bash
# Demo Completo - Banner Scanner com Nmap, Nuclei e Metasploit
# Para uso no Kali Linux

set -e  # Parar em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para log
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ❌ $1${NC}"
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    DEMO COMPLETO                            ║
║              Banner Scanner + Integração                    ║
║         Nmap + Nuclei + Metasploit + Relatórios            ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Verificar se estamos no diretório correto
if [ ! -f "ScanBanner.py" ]; then
    log_error "ScanBanner.py não encontrado. Execute este script no diretório do projeto."
    exit 1
fi

# Verificar dependências
log "Verificando dependências..."

deps=("python3" "nmap" "nuclei" "msfconsole" "whois")
missing=()

for dep in "${deps[@]}"; do
    if command -v "$dep" &> /dev/null; then
        log_success "$dep encontrado"
    else
        log_error "$dep NÃO encontrado"
        missing+=("$dep")
    fi
done

if [ ${#missing[@]} -ne 0 ]; then
    log_error "Dependências faltando: ${missing[*]}"
    log "Instale as dependências antes de continuar."
    exit 1
fi

# Criar diretório para resultados
RESULT_DIR="demo_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULT_DIR"
log "Resultados serão salvos em: $RESULT_DIR"

# Alvos de teste
TARGETS=("scanme.nmap.org" "testphp.vulnweb.com")

echo
log "🎯 INICIANDO DEMONSTRAÇÃO COMPLETA"
echo "═══════════════════════════════════════════════════════════════"

# Demo 1: Scan Básico
echo
log "📡 DEMO 1: Scan Básico (Nmap + Banners + WHOIS)"
echo "───────────────────────────────────────────────────────────────"

python3 ScanBanner.py -t "${TARGETS[0]}" \
    -o "$RESULT_DIR/demo1_basico.json" \
    -v

log_success "Demo 1 concluído. Resultado: $RESULT_DIR/demo1_basico.json"

# Demo 2: Scan com Nuclei
echo
log "🔍 DEMO 2: Scan com Nuclei (Vulnerabilidades)"
echo "───────────────────────────────────────────────────────────────"

python3 ScanBanner.py -t "${TARGETS[0]}" \
    --nuclei quick \
    -o "$RESULT_DIR/demo2_nuclei.json" \
    -v

log_success "Demo 2 concluído. Resultado: $RESULT_DIR/demo2_nuclei.json"

# Demo 3: Scan com Metasploit (Verify)
echo
log "🛡️  DEMO 3: Scan com Metasploit (Modo Verify - SEGURO)"
echo "───────────────────────────────────────────────────────────────"

python3 ScanBanner.py -t "${TARGETS[0]}" \
    --metasploit verify \
    -o "$RESULT_DIR/demo3_metasploit.json" \
    -v

log_success "Demo 3 concluído. Resultado: $RESULT_DIR/demo3_metasploit.json"

# Demo 4: Scan Completo
echo
log "🚀 DEMO 4: Scan Completo (Nmap + Nuclei + Metasploit)"
echo "───────────────────────────────────────────────────────────────"

python3 ScanBanner.py -t "${TARGETS[0]}" \
    --nuclei comprehensive \
    --nuclei-tags cve,rce,sqli \
    --metasploit verify \
    -o "$RESULT_DIR/demo4_completo.json" \
    -v

log_success "Demo 4 concluído. Resultado: $RESULT_DIR/demo4_completo.json"

# Demo 5: Múltiplos Alvos
echo
log "📋 DEMO 5: Múltiplos Alvos"
echo "───────────────────────────────────────────────────────────────"

# Criar arquivo de alvos
echo "# Alvos de demonstração" > "$RESULT_DIR/alvos_demo.txt"
for target in "${TARGETS[@]}"; do
    echo "$target" >> "$RESULT_DIR/alvos_demo.txt"
done

python3 ScanBanner.py -f "$RESULT_DIR/alvos_demo.txt" \
    --nuclei quick \
    --metasploit verify \
    --delay 2 \
    -o "$RESULT_DIR/demo5_multiplos.json" \
    -v

log_success "Demo 5 concluído. Resultado: $RESULT_DIR/demo5_multiplos.json"

# Demo 6: Modo Audit
echo
log "🔒 DEMO 6: Modo Audit (Simulação Segura)"
echo "───────────────────────────────────────────────────────────────"

python3 ScanBanner.py -t "${TARGETS[0]}" \
    --audit \
    --nuclei comprehensive \
    --metasploit exploit \
    --metasploit-confirm \
    -o "$RESULT_DIR/demo6_audit.json" \
    -v

log_success "Demo 6 concluído. Resultado: $RESULT_DIR/demo6_audit.json"

# Demo 7: Relatório HTML
echo
log "📊 DEMO 7: Relatório HTML"
echo "───────────────────────────────────────────────────────────────"

python3 ScanBanner.py -t "${TARGETS[1]}" \
    --nuclei quick \
    --metasploit verify \
    -o "$RESULT_DIR/demo7_relatorio.html" \
    -v

log_success "Demo 7 concluído. Resultado: $RESULT_DIR/demo7_relatorio.html"

# Análise dos Resultados
echo
log "📈 ANÁLISE DOS RESULTADOS"
echo "═══════════════════════════════════════════════════════════════"

# Verificar se jq está disponível para análise JSON
if command -v jq &> /dev/null; then
    echo
    log "🔍 Resumo dos Scans (usando jq):"
    
    for json_file in "$RESULT_DIR"/*.json; do
        if [ -f "$json_file" ]; then
            echo
            log "Arquivo: $(basename "$json_file")"
            
            # Extrair informações básicas
            if jq -e '.summary' "$json_file" &> /dev/null; then
                echo "  📊 Resumo:"
                jq -r '.summary | to_entries[] | "    \(.key): \(.value)"' "$json_file" 2>/dev/null || echo "    Erro ao processar resumo"
            fi
            
            # Extrair riscos
            if jq -e '.results[].risk_assessment' "$json_file" &> /dev/null; then
                echo "  ⚠️  Avaliação de Risco:"
                jq -r '.results[].risk_assessment | "    Nível: \(.risk_level) (Score: \(.risk_score))"' "$json_file" 2>/dev/null || echo "    Erro ao processar riscos"
            fi
        fi
    done
else
    log_warning "jq não encontrado. Instale para análise detalhada dos JSONs."
    log "Comando: sudo apt install jq"
fi

# Listar todos os arquivos gerados
echo
log "📁 ARQUIVOS GERADOS:"
ls -la "$RESULT_DIR"/

# Instruções finais
echo
log "🎉 DEMONSTRAÇÃO COMPLETA FINALIZADA!"
echo "═══════════════════════════════════════════════════════════════"
echo
log "📋 PRÓXIMOS PASSOS:"
echo "   1. Examine os arquivos JSON em: $RESULT_DIR/"
echo "   2. Abra o relatório HTML no navegador"
echo "   3. Compare os diferentes modos de scan"
echo "   4. Teste com seus próprios alvos (autorizados!)"
echo
log "🔧 COMANDOS ÚTEIS:"
echo "   # Visualizar JSON com jq:"
echo "   cat $RESULT_DIR/demo4_completo.json | jq ."
echo
echo "   # Extrair apenas vulnerabilidades:"
echo "   cat $RESULT_DIR/demo4_completo.json | jq '.results[].nuclei_scan.vulnerabilities'"
echo
echo "   # Extrair exploits encontrados:"
echo "   cat $RESULT_DIR/demo4_completo.json | jq '.results[].metasploit_scan.exploits_found'"
echo
echo "   # Abrir relatório HTML:"
echo "   firefox $RESULT_DIR/demo7_relatorio.html &"
echo
log_success "Demo concluído com sucesso! 🚀"

# Verificar se há relatório HTML para abrir
if [ -f "$RESULT_DIR/demo7_relatorio.html" ]; then
    echo
    read -p "Deseja abrir o relatório HTML no navegador? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v firefox &> /dev/null; then
            firefox "$RESULT_DIR/demo7_relatorio.html" &
            log_success "Relatório HTML aberto no Firefox"
        elif command -v google-chrome &> /dev/null; then
            google-chrome "$RESULT_DIR/demo7_relatorio.html" &
            log_success "Relatório HTML aberto no Chrome"
        else
            log_warning "Navegador não encontrado. Abra manualmente: $RESULT_DIR/demo7_relatorio.html"
        fi
    fi
fi

echo
log "🔒 LEMBRE-SE: Use apenas em alvos autorizados!"
log "📚 Consulte a documentação em README.md e metasploit_examples.md"