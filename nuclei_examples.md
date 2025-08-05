# 🎯 Nuclei Integration Examples

## Installation Requirements

Before using Nuclei features, make sure you have Nuclei installed:

```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates
```

## Usage Examples

### 1. Quick Vulnerability Scan
```bash
python3 ScanBanner.py -t example.com --nuclei quick
```
- Fast scan focusing on critical and high severity vulnerabilities
- Recommended for initial reconnaissance

### 2. Comprehensive Scan (Default)
```bash
python3 ScanBanner.py -t example.com --nuclei comprehensive
```
- Full scan with all available templates
- Best for thorough security assessment

### 3. Critical Vulnerabilities Only
```bash
python3 ScanBanner.py -t example.com --nuclei critical
```
- Focuses only on critical severity findings
- Ideal for quick security checks

### 4. Custom Template Tags
```bash
# CVE-specific scan
python3 ScanBanner.py -t example.com --nuclei-tags cve

# Web application vulnerabilities
python3 ScanBanner.py -t example.com --nuclei-tags sqli,xss,rce

# Exposed panels and admin interfaces
python3 ScanBanner.py -t example.com --nuclei-tags panel,login,admin

# Technology detection
python3 ScanBanner.py -t example.com --nuclei-tags tech,detect
```

### 5. Disable Nuclei Scan
```bash
python3 ScanBanner.py -t example.com --nuclei off
```
- Runs only Nmap, WHOIS, and banner collection
- Faster execution when vulnerability scanning is not needed

### 6. Multiple Targets with Nuclei
```bash
python3 ScanBanner.py -f targets.txt --nuclei comprehensive -o results.json
```

### 7. Audit Mode with Nuclei
```bash
python3 ScanBanner.py -t example.com --audit --nuclei comprehensive
```
- Simulates Nuclei scan without actual execution
- Safe for testing and demonstration

## Popular Template Tags

| Tag | Description | Example Usage |
|-----|-------------|---------------|
| `cve` | CVE vulnerabilities | `--nuclei-tags cve` |
| `rce` | Remote Code Execution | `--nuclei-tags rce` |
| `sqli` | SQL Injection | `--nuclei-tags sqli` |
| `xss` | Cross-Site Scripting | `--nuclei-tags xss` |
| `lfi` | Local File Inclusion | `--nuclei-tags lfi` |
| `ssrf` | Server-Side Request Forgery | `--nuclei-tags ssrf` |
| `panel` | Admin/Login Panels | `--nuclei-tags panel` |
| `exposure` | Information Disclosure | `--nuclei-tags exposure` |
| `misconfig` | Misconfigurations | `--nuclei-tags misconfig` |
| `tech` | Technology Detection | `--nuclei-tags tech` |

## Output Integration

Nuclei results are automatically integrated into the main report:

```json
{
  "target": "example.com",
  "nuclei_scan": {
    "vulnerabilities": [...],
    "info_disclosures": [...],
    "misconfigurations": [...],
    "exposed_panels": [...],
    "technologies": [...],
    "total_findings": 15,
    "severity_stats": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2,
      "info": 0
    }
  }
}
```

## Performance Considerations

- **Quick scan**: ~2-5 minutes per target
- **Comprehensive scan**: ~5-15 minutes per target
- **Critical scan**: ~3-8 minutes per target
- **Custom tags**: Varies based on template count

## Best Practices

1. **Start with quick scans** for initial assessment
2. **Use specific tags** when targeting known technologies
3. **Run comprehensive scans** for thorough security audits
4. **Combine with other tools** for complete reconnaissance
5. **Always ensure authorization** before scanning targets

## Troubleshooting

### Nuclei Not Found
```
[WARNING] Nuclei não disponível - pulando scan de vulnerabilidades
```
**Solution**: Install Nuclei and ensure it's in your PATH

### Templates Not Updated
```bash
nuclei -update-templates
```

### Slow Performance
- Use `--nuclei quick` for faster scans
- Use specific `--nuclei-tags` to reduce template count
- Consider using `--nuclei off` if vulnerability scanning is not needed