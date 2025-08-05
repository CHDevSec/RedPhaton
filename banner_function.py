def display_banner():
    """Displays the main tool banner"""
    # Colors for the banner
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    banner = f"""
{CYAN}{RESET}                                                                              
{CYAN}{RESET}  {RED}██▀███  ▓█████ ▓█████▄  ██▓███   ██░ ██  ▄▄▄     ▄▄▄█████▓ ▒█████   ███▄    █{RESET} 
{CYAN}{RESET} {RED}▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓██░  ██▒▓██░ ██▒▒████▄   ▓  ██▒ ▓▒▒██▒  ██▒ ██ ▀█   █{RESET} 
{CYAN}{RESET} {RED}▓██ ░▄█ ▒▒███   ░██   █▌▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄ ▒ ▓██░ ▒░▒██░  ██▒▓██  ▀█ ██▒{RESET}
{CYAN}{RESET} {RED}▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██░ ▓██▓ ░ ▒██   ██░▓██▒  ▐▌██▒{RESET}
{CYAN}{RESET} {RED}░██▓ ▒██▒░▒████▒░▒████▓ ▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒ ▒██▒ ░ ░ ████▓▒░▒██░   ▓██░{RESET}
{CYAN}{RESET} {RED}░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒ ▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░ ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ▒ ▒{RESET} 
{CYAN}{RESET} {RED}  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒ ░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░   ░      ░ ▒ ▒░ ░ ░░   ░ ▒░{RESET}
{CYAN}{RESET} {RED}  ░░   ░    ░    ░ ░  ░ ░░        ░  ░░ ░  ░   ▒    ░      ░ ░ ░ ▒     ░   ░ ░{RESET} 
{CYAN}{RESET} {RED}   ░        ░  ░   ░              ░  ░  ░      ░  ░            ░ ░           ░{RESET} 
{CYAN}{RESET} {RED}                 ░                                                              {RESET}                                         
{CYAN}{RESET}                                                                              
{CYAN}╔════════════════════════════════════════════════════════════════════╗{RESET}
{CYAN}║{RESET}  {BOLD}{WHITE}🔥 RedPhantom - Advanced Red Team Framework v3.0{RESET}                {CYAN}║{RESET}
{CYAN}║{RESET}  {YELLOW}👨‍💻 Developed by: Caio Henrique{RESET}  {GREEN}👻 Phantom Stealth Capabilities{RESET}  {CYAN}║{RESET}
{CYAN}║{RESET}  {BLUE}💀 Zero-Day Discovery • C2 Framework • Advanced Persistence{RESET}        {CYAN}║{RESET}
{CYAN}╚════════════════════════════════════════════════════════════════════╝{RESET}
    """
    
    print(banner)

def display_help_banner():
    """Displays complete banner with usage information"""
    display_banner()
    
    # Cores
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    help_text = f"""
{BOLD}{WHITE}📋 HOW TO USE:{RESET}

{YELLOW}🎯 Single Target Scan:{RESET}
  {GREEN}python3 RedPhantom.py -t 192.168.1.1{RESET}
  {GREEN}python3 RedPhantom.py -t example.com -v{RESET}
  {GREEN}python3 RedPhantom.py -t target.com --audit -v{RESET}

{YELLOW}📁 Multiple Targets Scan:{RESET}
  {GREEN}python3 RedPhantom.py -f targets.txt{RESET}
  {GREEN}python3 RedPhantom.py -f targets.csv -o results.json{RESET}

{YELLOW}⚙️  Main Options:{RESET}
  {BLUE}-t, --target{RESET}     Single target (IP or domain)
  {BLUE}-f, --file{RESET}       File with target list
  {BLUE}-o, --output{RESET}     Output file (JSON/CSV/HTML)
  {BLUE}-v, --verbose{RESET}    Verbose mode (detailed)
  {BLUE}--audit{RESET}          Audit mode (no real scans)
  {BLUE}--nuclei{RESET}         Nuclei scan type (quick/comprehensive/critical/off)
  {BLUE}--nuclei-tags{RESET}    Specific Nuclei template tags
  {BLUE}--timeout{RESET}        Connection timeout (default: 5s)
  {BLUE}--threads{RESET}        Number of threads (default: 10)

{YELLOW}🔍 Features:{RESET}
  {MAGENTA}•{RESET} Port scanning with Nmap
  {MAGENTA}•{RESET} Service banner collection
  {MAGENTA}•{RESET} WHOIS and DNS analysis
  {MAGENTA}•{RESET} Web technology detection
  {MAGENTA}•{RESET} Nuclei vulnerability scanning (4000+ templates)
  {MAGENTA}•{RESET} Risk and vulnerability assessment
  {MAGENTA}•{RESET} Reports in multiple formats

{YELLOW}⚠️  Legal Warning:{RESET}
  {CYAN}This tool should only be used on authorized systems.{RESET}
  {CYAN}Unauthorized use may violate local and international laws.{RESET}

{BOLD}{WHITE}🚀 Advanced Examples:{RESET}
  {GREEN}python3 RedPhantom.py -t company.com -v --nuclei comprehensive{RESET}
  {GREEN}python3 RedPhantom.py -f targets.txt --nuclei critical -o report.html{RESET}
  {GREEN}python3 RedPhantom.py -t target.com --nuclei-tags cve,rce,sqli{RESET}

{BOLD}{YELLOW}For more information, visit: https://github.com/chdevsec{RESET}
    """
    
    print(help_text)


