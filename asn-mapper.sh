#!/bin/bash

# Tesla ASN Recon Toolkit - Enhanced
# Author: Bug Bounty Hunter Toolkit
# Description: A fast and comprehensive surface mapper using ASN or domain input.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ASCII Banner
function display_banner() {
  echo -e "${BLUE}"
  figlet -f slant "ASN Mapper Pro" | lolcat
  echo -e "${NC}"
  echo -e "${YELLOW}Version: 2.0 | Enhanced Reconnaissance Toolkit${NC}"
  echo -e "${GREEN}------------------------------------------------${NC}"
}

# Help menu
function usage() {
  echo -e "\n${BLUE}Usage:${NC}"
  echo -e "  $0 -t <target.com> [-p <ports>] [-r <rate>] [-o <output>] [-T <threads>]"
  echo -e "  $0 -A <ASN> [-p <ports>] [-r <rate>] [-o <output>] [-T <threads>]"
  echo -e "\n${YELLOW}Options:${NC}"
  echo -e "  -t    Target domain name (e.g. tesla.com)"
  echo -e "  -A    ASN number (e.g. AS394161)"
  echo -e "  -p    Ports to scan (default: 80,443,8080,8443)"
  echo -e "  -r    Masscan scan rate (default: 5000)"
  echo -e "  -o    Output file name (default: asn_recon_<timestamp>.txt)"
  echo -e "  -T    Threads for parallel processing (default: 10)"
  echo -e "  -v    Enable verbose output"
  echo -e "  -h    Show this help menu"
  echo -e "\n${GREEN}Examples:${NC}"
  echo -e "  $0 -t tesla.com -p 80,443,8080 -o tesla_assets.txt"
  echo -e "  $0 -A AS394161 -r 10000 -T 20 -o asn_scan_results.txt"
  exit 1
}

# Initialize variables
PORTS="80,443,8080,8443"
RATE=5000
THREADS=10
VERBOSE=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT="asn_recon_$TIMESTAMP.txt"

# Check dependencies
function check_dependencies() {
  local tools=("figlet" "lolcat" "whois" "masscan" "nmap" "subfinder" "amass" "httpx" "jq" "dig")
  local missing=()
  
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      missing+=("$tool")
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${RED}[!] Missing dependencies:${NC}"
    for dep in "${missing[@]}"; do
      echo -e "  - $dep"
    done
    echo -e "\nInstall them with: sudo apt install ${missing[*]}"
    exit 1
  fi
}

# Parse arguments
while getopts "t:A:p:r:o:T:vh" opt; do
  case $opt in
    t) TARGET=$OPTARG;;
    A) ASN=$OPTARG;;
    p) PORTS=$OPTARG;;
    r) RATE=$OPTARG;;
    o) OUTPUT=$OPTARG;;
    T) THREADS=$OPTARG;;
    v) VERBOSE=true;;
    h) usage;;
    *) usage;;
  esac
done

# Validate arguments
if [[ -z $TARGET && -z $ASN ]]; then
  echo -e "${RED}[!] Error: Either target (-t) or ASN (-A) must be specified${NC}"
  usage
fi

if [[ ! -z "$TARGET" && ! -z "$ASN" ]]; then
  echo -e "${YELLOW}[!] Warning: Both target and ASN specified. Using target for ASN discovery.${NC}"
fi

# Discover ASN from target
function discover_asn() {
  echo -e "${BLUE}[*] Discovering ASN for $TARGET...${NC}"
  
  # Known Tesla ASNs
  local TESLA_ASNS=("AS394161" "AS56590" "AS398324" "AS35994")
  
  # First try direct IP lookup
  DOMAIN_IP=$(dig +short "$TARGET" | head -1)
  [[ -z "$DOMAIN_IP" ]] && { echo -e "${RED}[!] Could not resolve IP for $TARGET${NC}"; exit 1; }
  
  echo -e "${GREEN}[+] Resolved IP: $DOMAIN_IP${NC}"
  
  # Try multiple ASN lookup methods
  for method in whois bgpview hackertarget; do
    case $method in
      whois)
        ASN=$(whois "$DOMAIN_IP" | grep -iE 'originas|origin|aut-num' | head -1 | awk '{print $NF}' | grep -Eo 'AS[0-9]+')
        ;;
      bgpview)
        ASN=$(curl -s "https://api.bgpview.io/ip/$DOMAIN_IP" 2>/dev/null | jq -r '.data.prefixes[].asn.asn' 2>/dev/null | head -1)
        [[ -n "$ASN" ]] && ASN="AS$ASN"
        ;;
      hackertarget)
        ASN=$(curl -s "https://api.hackertarget.com/aslookup/?q=$DOMAIN_IP" 2>/dev/null | grep -Eo 'AS[0-9]+' | head -1)
        ;;
    esac
    
    # Verify if found ASN is in known Tesla ASNs
    if [[ -n "$ASN" ]] && [[ " ${TESLA_ASNS[@]} " =~ " ${ASN} " ]]; then
      echo -e "${GREEN}[+] Found Tesla ASN: $ASN${NC}"
      return
    fi
  done
  
  # If no ASN found or not a known Tesla ASN
  echo -e "${YELLOW}[!] Could not discover valid ASN for $TARGET${NC}"
  echo -e "${YELLOW}[!] Using known Tesla ASN: AS394161 instead${NC}"
  ASN="AS394161"
}

# Scan ASN networks
function scan_asn() {
  echo -e "${BLUE}[*] Collecting IP ranges for $ASN...${NC}"
  whois -h whois.radb.net -- "-i origin $ASN" | \
    grep -Eo '([0-9.]+){4}/[0-9]+' | sort -u > recon/ips/ip_ranges.txt
  
  local range_count=$(wc -l < recon/ips/ip_ranges.txt)
  echo -e "${GREEN}[+] Found $range_count IP ranges${NC}"
  
  if [ "$range_count" -gt 100 ]; then
    echo -e "${YELLOW}[!] Large network detected. Consider using a higher scan rate (-r)${NC}"
  fi

  echo -e "${BLUE}[*] Scanning with Masscan (Rate: $RATE, Threads: $THREADS)...${NC}"
  xargs -a recon/ips/ip_ranges.txt -I {} -P "$THREADS" \
    masscan {} -p"$PORTS" --rate="$RATE" --open -oG recon/scans/masscan_raw.txt 2>/dev/null || true
  
  grep -Eo '([0-9]+\.){3}[0-9]+' recon/scans/masscan_raw.txt | sort -u > recon/ips/live_ips.txt
  local ip_count=$(wc -l < recon/ips/live_ips.txt)
  echo -e "${GREEN}[+] Found $ip_count live IPs${NC}"

  if [ "$ip_count" -gt 0 ]; then
    echo -e "${BLUE}[*] Running Nmap service detection...${NC}"
    nmap -sV -p "$PORTS" -iL recon/ips/live_ips.txt -oN recon/scans/nmap_scan.txt --min-rate 1000
    
    echo -e "${BLUE}[*] Gathering SSL certificate information...${NC}"
    while read ip; do
      for port in 443 8443; do
        timeout 2 openssl s_client -connect "$ip:$port" -servername "$TARGET" < /dev/null 2>/dev/null | \
          openssl x509 -noout -text > "recon/ssl/${ip}_${port}.crt" 2>/dev/null
      done
    done < recon/ips/live_ips.txt
  fi
}

# Discover subdomains
function discover_subdomains() {
  [[ -z "$TARGET" ]] && return
  
  echo -e "${BLUE}[*] Running Subfinder...${NC}"
  subfinder -d "$TARGET" -silent > recon/subs/subfinder.txt 2>/dev/null || true
  
  echo -e "${BLUE}[*] Running Amass ASN scan...${NC}"
  amass intel -asn "${ASN#AS}" -whois -ip > recon/subs/amass_asn.txt 2>/dev/null || true
  
  echo -e "${BLUE}[*] Consolidating subdomains...${NC}"
  cat recon/subs/*.txt 2>/dev/null | cut -d ' ' -f1 | sort -u > recon/subs/all_subs.txt
  
  local sub_count=$(wc -l < recon/subs/all_subs.txt 2>/dev/null || echo 0)
  echo -e "${GREEN}[+] Found $sub_count unique subdomains${NC}"
  
  if [ "$sub_count" -gt 0 ]; then
    echo -e "${BLUE}[*] Probing live domains...${NC}"
    httpx -l recon/subs/all_subs.txt -title -status-code -tech-detect -ip -o recon/live/live_hosts.txt -threads "$THREADS" 2>/dev/null || true
  fi
}

# Finalize output
function finalize_output() {
  echo -e "${BLUE}[*] Generating final report...${NC}"
  
  # Create header
  echo "ASN Reconnaissance Report" > "$OUTPUT"
  echo "Generated: $(date)" >> "$OUTPUT"
  echo "Target: ${TARGET:-N/A}" >> "$OUTPUT"
  echo "ASN: ${ASN:-N/A}" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  
  # Add IP information
  echo "=== IP Ranges ===" >> "$OUTPUT"
  cat recon/ips/ip_ranges.txt >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  
  # Add live hosts
  if [ -f recon/live/live_hosts.txt ]; then
    echo "=== Live Hosts ===" >> "$OUTPUT"
    cat recon/live/live_hosts.txt >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  fi
  
  # Add nmap summary
  if [ -f recon/scans/nmap_scan.txt ]; then
    echo "=== Service Scan Summary ===" >> "$OUTPUT"
    grep -E '^[0-9]+/tcp' recon/scans/nmap_scan.txt >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  fi
  
  echo -e "${GREEN}[+] Reconnaissance complete. Results saved to $OUTPUT${NC}"
  echo -e "${BLUE}------------------------------------------------${NC}"
}

# Main function
function main() {
  display_banner
  check_dependencies
  
  mkdir -p recon/{ips,subs,live,scans,ssl}
  
  if [[ ! -z "$TARGET" ]]; then
    echo -e "${GREEN}[+] Starting reconnaissance for target: $TARGET${NC}"
    discover_asn
  fi

  if [[ ! -z "$ASN" ]]; then
    echo -e "${GREEN}[+] Starting ASN reconnaissance for: $ASN${NC}"
    scan_asn
  fi

  if [[ ! -z "$TARGET" ]]; then
    discover_subdomains
  fi

  finalize_output
}

main
exit 0
