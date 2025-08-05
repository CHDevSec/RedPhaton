#!/bin/bash
# 🔥 BLACKHAT SCANNER INSTALLATION SCRIPT 🔥
# Instala todas as dependências necessárias para o modo Black Hat

echo "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"
echo "🔥                    BLACK HAT SCANNER INSTALLER                    🔥"
echo "🔥                     NÍVEL MÁXIMO DE AGRESSIVIDADE                 🔥"
echo "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"
echo ""
echo "⚠️  ATENÇÃO: Esta ferramenta é destinada APENAS para:"
echo "    - Testes de penetração autorizados"
echo "    - Exercícios de Red Team aprovados"
echo "    - Ambientes de laboratório controlados"
echo "    - Pesquisa de segurança ética"
echo ""
echo "🚨 NÃO USE contra sistemas que você não possui ou não tem autorização!"
echo ""

# Verificar se é root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  Este script não deve ser executado como root para algumas dependências."
   echo "   Continuando com instalação..."
fi

# Função para detectar distribuição
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VERSION=$(lsb_release -sr)
    else
        DISTRO="unknown"
        VERSION="unknown"
    fi
}

# Função para instalar dependências base
install_base_deps() {
    echo "📦 Instalando dependências base..."
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv git curl wget
            sudo apt install -y nmap whois dnsutils netcat-openbsd
            sudo apt install -y build-essential libssl-dev libffi-dev
            sudo apt install -y smbclient ftp telnet
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                sudo dnf install -y python3 python3-pip git curl wget
                sudo dnf install -y nmap whois bind-utils nc
                sudo dnf install -y gcc openssl-devel libffi-devel
                sudo dnf install -y samba-client ftp telnet
            else
                sudo yum install -y python3 python3-pip git curl wget
                sudo yum install -y nmap whois bind-utils nc
                sudo yum install -y gcc openssl-devel libffi-devel
                sudo yum install -y samba-client ftp telnet
            fi
            ;;
        arch)
            sudo pacman -Sy python python-pip git curl wget
            sudo pacman -Sy nmap whois dnsutils openbsd-netcat
            sudo pacman -Sy base-devel openssl libffi
            sudo pacman -Sy smbclient inetutils
            ;;
        *)
            echo "⚠️  Distribuição não reconhecida. Instale manualmente:"
            echo "   - Python 3.8+"
            echo "   - pip3"
            echo "   - nmap"
            echo "   - whois"
            echo "   - git"
            ;;
    esac
}

# Função para instalar Golang (necessário para Nuclei)
install_golang() {
    echo "🐹 Instalando Go (necessário para Nuclei)..."
    
    if command -v go &> /dev/null; then
        echo "✅ Go já está instalado: $(go version)"
        return
    fi
    
    GO_VERSION="1.21.5"
    
    case $(uname -m) in
        x86_64)
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            ;;
        *)
            echo "⚠️  Arquitetura não suportada para instalação automática do Go"
            return
            ;;
    esac
    
    cd /tmp
    wget "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    
    # Adicionar Go ao PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    echo "✅ Go instalado: $(go version)"
}

# Função para instalar Nuclei
install_nuclei() {
    echo "⚡ Instalando Nuclei..."
    
    if command -v nuclei &> /dev/null; then
        echo "✅ Nuclei já está instalado: $(nuclei -version)"
        return
    fi
    
    # Instalar via Go
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    # Verificar instalação
    if command -v nuclei &> /dev/null; then
        echo "✅ Nuclei instalado com sucesso"
        
        # Baixar templates
        echo "📚 Baixando templates do Nuclei..."
        nuclei -update-templates
    else
        echo "❌ Falha na instalação do Nuclei"
    fi
}

# Função para tentar instalar Metasploit
install_metasploit() {
    echo "🎯 Verificando Metasploit Framework..."
    
    if command -v msfconsole &> /dev/null; then
        echo "✅ Metasploit já está instalado"
        return
    fi
    
    echo "📥 Metasploit não encontrado. Instruções de instalação:"
    echo ""
    echo "🔗 Para Ubuntu/Debian:"
    echo "   curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall"
    echo "   chmod 755 msfinstall"
    echo "   ./msfinstall"
    echo ""
    echo "🔗 Para outras distribuições:"
    echo "   https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers"
    echo ""
    echo "⚠️  Metasploit é uma dependência opcional, mas recomendada para máxima efetividade"
}

# Função para criar ambiente virtual Python
setup_python_env() {
    echo "🐍 Configurando ambiente Python..."
    
    # Criar ambiente virtual
    python3 -m venv blackhat_env
    source blackhat_env/bin/activate
    
    # Atualizar pip
    pip install --upgrade pip
    
    # Instalar dependências
    echo "📦 Instalando dependências Python..."
    pip install -r requirements.txt
    
    echo "✅ Ambiente Python configurado"
}

# Função para verificar permissões
check_permissions() {
    echo "🔐 Verificando permissões..."
    
    # Verificar se pode executar nmap como raw sockets
    if ! nmap -sS 127.0.0.1 -p 80 >/dev/null 2>&1; then
        echo "⚠️  Para scans SYN, pode ser necessário executar como root:"
        echo "   sudo python3 ScanBanner.py --target example.com --blackhat"
    fi
    
    # Verificar acesso a /etc/hosts
    if [ ! -r /etc/hosts ]; then
        echo "⚠️  Sem acesso de leitura a /etc/hosts"
    fi
}

# Função para criar configuração
create_config() {
    echo "⚙️  Criando configuração..."
    
    mkdir -p config
    cat > config/blackhat_config.json << EOF
{
    "general": {
        "max_threads": 50,
        "timeout": 60,
        "rate_limit": 100,
        "debug": false
    },
    "exploits": {
        "enable_zero_days": true,
        "max_exploit_time": 30,
        "verify_exploits": true,
        "auto_exploit": false
    },
    "evasion": {
        "enable_waf_bypass": true,
        "max_encoding_depth": 3,
        "test_all_techniques": true,
        "randomize_user_agents": true
    },
    "ai": {
        "confidence_threshold": 0.7,
        "max_mutations": 20,
        "enable_ml_detection": true,
        "learning_mode": true
    },
    "fuzzing": {
        "max_payloads": 100,
        "intelligent_mutation": true,
        "polyglot_focus": true
    },
    "lateral_movement": {
        "max_pivot_depth": 3,
        "auto_credential_harvest": true,
        "enable_pass_the_hash": true
    }
}
EOF
    
    echo "✅ Configuração criada em config/blackhat_config.json"
}

# Função para testar instalação
test_installation() {
    echo "🧪 Testando instalação..."
    
    # Ativar ambiente virtual
    source blackhat_env/bin/activate
    
    # Teste básico
    echo "📋 Executando teste básico..."
    if python3 ScanBanner.py --help >/dev/null 2>&1; then
        echo "✅ Scanner principal funcionando"
    else
        echo "❌ Erro no scanner principal"
        return 1
    fi
    
    # Teste modo audit
    echo "📋 Testando modo audit..."
    if python3 ScanBanner.py --target 127.0.0.1 --blackhat --audit >/dev/null 2>&1; then
        echo "✅ Modo Black Hat funcionando"
    else
        echo "❌ Erro no modo Black Hat"
        return 1
    fi
    
    echo "✅ Todos os testes passaram!"
}

# Função para mostrar instruções finais
show_final_instructions() {
    echo ""
    echo "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉"
    echo "🎉                     INSTALAÇÃO CONCLUÍDA!                     🎉"
    echo "🎉                    BLACK HAT MODE PRONTO!                     🎉"
    echo "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉"
    echo ""
    echo "🚀 COMO USAR:"
    echo ""
    echo "1. Ativar ambiente virtual:"
    echo "   source blackhat_env/bin/activate"
    echo ""
    echo "2. Executar scan Black Hat:"
    echo "   python3 ScanBanner.py --target example.com --blackhat"
    echo ""
    echo "3. Scan com lista de alvos:"
    echo "   python3 ScanBanner.py --file targets.txt --blackhat --output relatorio.html"
    echo ""
    echo "4. Modo audit (sem execução real):"
    echo "   python3 ScanBanner.py --target example.com --blackhat --audit"
    echo ""
    echo "🔥 RECURSOS DISPONÍVEIS:"
    echo "   💀 Exploits Zero-Day (CVEs 2024)"
    echo "   🎭 Técnicas de Evasão WAF/IDS/IPS"
    echo "   🧠 Detecção por Inteligência Artificial"
    echo "   🎯 Payloads Políglotas e Fuzzing"
    echo "   🔗 Auto-Pivoting e Movimento Lateral"
    echo ""
    echo "⚠️  LEMBRE-SE: USE APENAS EM AMBIENTES AUTORIZADOS!"
    echo ""
    echo "📚 Documentação completa: BLACKHAT_MODE.md"
    echo "🐛 Relatórios de bugs: https://github.com/seu-repo/issues"
    echo ""
}

# MAIN EXECUTION
main() {
    echo "🚀 Iniciando instalação do Black Hat Scanner..."
    
    # Detectar distribuição
    detect_distro
    echo "🔍 Sistema detectado: $DISTRO $VERSION"
    
    # Instalar dependências base
    install_base_deps
    
    # Instalar Go
    install_golang
    
    # Instalar Nuclei
    install_nuclei
    
    # Verificar Metasploit
    install_metasploit
    
    # Configurar Python
    setup_python_env
    
    # Verificar permissões
    check_permissions
    
    # Criar configuração
    create_config
    
    # Testar instalação
    test_installation
    
    # Mostrar instruções
    show_final_instructions
}

# Executar instalação
main "$@"