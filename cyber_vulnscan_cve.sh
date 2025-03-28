#!/bin/bash

# Vulnerability Scanner by Cyber Defense Academy
# Creator: Cyber Defense Academy
# GitHub: https://github.com/cyberdefenseacademy
# X: https://X.com/cyberdefaca
# YouTube: https://www.youtube.com/@CyberDefenseAcademy

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Run as root (sudo) for full functionality.${NC}"
    exit 1
fi

# ASCII Art Banner
clear
echo -e "${CYAN}"
cat << "EOF"
   ____        _               _____       _            
  / __ \      (_)             |  __ \     (_)           
 | /  \/ __ _ _ _ __   __ _  | |  \/_   _ _ _ __   __ _ 
 | |    / _` | | '_ \ / _` | | | __| | | | | '_ \ / _` |
 | \__/\ (_| | | | | | (_| | | |_\ \ |_| | | | | | (_| |
  \____/\__,_|_|_| |_|__,_|  \____/\__,_|_|_| |_|__,_| 
  Cyber Defense Academy - Vulnerability Scanner v1.0 
EOF
echo -e "${NC}"
echo "GitHub: https://github.com/cyberdefenseacademy"
echo "X: https://X.com/cyberdefaca"
echo "YouTube: https://www.youtube.com/@CyberDefenseAcademy"
echo -e "${YELLOW}-----------------------------------------------${NC}"

# Function to print results
print_result() {
    local risk="$1"
    local issue="$2"
    local detail="$3"
    case "$risk" in
        "High") COLOR="$RED" ;;
        "Medium") COLOR="$YELLOW" ;;
        "Low") COLOR="$GREEN" ;;
        *) COLOR="$NC" ;;
    esac
    echo -e "${COLOR}[$risk] $issue: $detail${NC}"
    RESULTS+=("$risk|$issue|$detail")
}

# Check tool availability
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${YELLOW}Warning: $1 not found. Install for full features.${NC}"
        return 1
    fi
    return 0
}

# Basic CVE lookup
check_cve() {
    local software="$1"
    local version="$2"
    if check_tool "jq"; then
        CVE_RESULT=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$software+$version" | jq -r '.vulnerabilities[]?.cve.id' 2>/dev/null | head -n 1)
        if [ -n "$CVE_RESULT" ]; then
            print_result "High" "CVE Detected" "$software $version - $CVE_RESULT"
            return 0
        fi
    fi
    if curl -s "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=$software+$version" | grep -qi "CVE-"; then
        print_result "High" "Potential CVE" "$software $version - Check NVD for details"
    fi
}

# Menu
show_menu() {
    echo -e "${GREEN}Select Scan Type:${NC}"
    echo "1. Web Vulnerability Scan (with CVE)"
    echo "2. Application File Scan (with CVE)"
    echo "3. API Vulnerability Scan (with CVE)"
    echo "4. Full System Scan (Web + API + Network + CVE)"
    echo "5. Exit"
    read -p "Choice [1-5]: " choice
}

# Web Scan with retry
web_scan() {
    local url="$1"
    echo -e "\n${CYAN}Scanning Web: $url${NC}"
    HEADERS=$(curl -s -I -m 10 "$url" 2>/tmp/curl_err || (sleep 2; curl -s -I -m 10 "$url" 2>/tmp/curl_err))
    if [ $? -ne 0 ]; then
        ERR=$(cat /tmp/curl_err)
        print_result "N/A" "Web connection failed" "Could not reach $url - Error: $ERR"
        rm -f /tmp/curl_err
        return
    fi
    rm -f /tmp/curl_err
    # CSP
    if ! echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
        print_result "Medium" "Missing CSP" "Increases XSS risk"
    fi
    # Server exposure + CVE
    SERVER=$(echo "$HEADERS" | grep -i "^Server:" | awk '{print $2}')
    if [ -n "$SERVER" ] && echo "$SERVER" | grep -qiE "apache|nginx"; then
        print_result "Low" "Server exposed" "$SERVER detected"
        SERVER_NAME=$(echo "$SERVER" | cut -d'/' -f1)
        SERVER_VER=$(echo "$SERVER" | cut -d'/' -f2)
        check_cve "$SERVER_NAME" "$SERVER_VER"
    fi
    # Directory listing
    BODY=$(curl -s -m 10 "$url" 2>/dev/null)
    if echo "$BODY" | grep -qi "index of"; then
        print_result "High" "Directory listing" "Exposes files"
    fi
    # Open redirect
    REDIRECT=$(curl -s -L -m 10 "$url/?redirect=https://evil.com" | grep -i "evil.com")
    if [ -n "$REDIRECT" ]; then
        print_result "High" "Open redirect" "Redirects to external domains"
    fi
    # SQL Injection
    SQL=$(curl -s -m 10 "$url/test' OR 1=1 --" | grep -i "sql syntax")
    if [ -n "$SQL" ]; then
        print_result "High" "SQL Injection" "Potential database vuln"
    fi
}

# App Scan
app_scan() {
    local file="$1"
    echo -e "\n${CYAN}Scanning App File: $file${NC}"
    if [ ! -f "$file" ]; then
        print_result "N/A" "File not found" "$file does not exist"
        return
    fi
    if check_tool "strings"; then
        SECRETS=$(strings "$file" | grep -iE "password|api_key|secret" | head -n 5)
        if [ -n "$SECRETS" ]; then
            print_result "High" "Hardcoded secrets" "Found: $SECRETS"
        fi
        VERSION=$(strings "$file" | grep -iE "version|v[0-9]" | head -n 1)
        if [ -n "$VERSION" ]; then
            APP_NAME=$(basename "$file" | cut -d'.' -f1)
            check_cve "$APP_NAME" "$VERSION"
        fi
    fi
    PERMS=$(stat -c "%a" "$file")
    if [ "$PERMS" -ge 666 ]; then
        print_result "Medium" "Weak permissions" "File perms: $PERMS"
    fi
}

# API Scan
api_scan() {
    local url="$1"
    echo -e "\n${CYAN}Scanning API: $url${NC}"
    HEADERS=$(curl -s -I -m 10 "$url" 2>/tmp/curl_err || (sleep 2; curl -s -I -m 10 "$url" 2>/tmp/curl_err))
    if [ $? -ne 0 ]; then
        ERR=$(cat /tmp/curl_err)
        print_result "N/A" "API connection failed" "Could not reach $url - Error: $ERR"
        rm -f /tmp/curl_err
        return
    fi
    rm -f /tmp/curl_err
    CORS=$(echo "$HEADERS" | grep -i "Access-Control-Allow-Origin:" | awk '{$1=""; print $0}')
    if [ "$CORS" = "*" ]; then
        print_result "Medium" "Weak CORS" "Allows all origins"
    fi
    RATE=$(curl -s -I -m 10 "$url" -H "X-Rate-Limit: 9999" | grep -i "429")
    if [ -z "$RATE" ]; then
        print_result "Medium" "No rate limiting" "Possible abuse risk"
    fi
    BODY=$(curl -s -m 10 "$url" 2>/dev/null)
    if echo "$BODY" | grep -qi "api_key"; then
        print_result "High" "API key exposure" "Key in response"
    fi
    SERVER=$(echo "$HEADERS" | grep -i "^Server:" | awk '{print $2}')
    if [ -n "$SERVER" ]; then
        SERVER_NAME=$(echo "$SERVER" | cut -d'/' -f1)
        SERVER_VER=$(echo "$SERVER" | cut -d'/' -f2)
        check_cve "$SERVER_NAME" "$SERVER_VER"
    fi
}

# Full Scan
full_scan() {
    local url="$1"
    local domain=$(echo "$url" | awk -F/ '{print $3}')
    web_scan "$url"
    api_scan "$url"
    echo -e "\n${CYAN}Scanning Network: $domain${NC}"
    if check_tool "nmap"; then
        NMAP=$(nmap -sV --script vuln "$domain" 2>/dev/null | grep -iE "CVE-|vulnerable")
        if [ -n "$NMAP" ]; then
            print_result "High" "Network CVEs" "nmap: $NMAP"
        else
            print_result "Low" "Network clean" "No CVEs detected"
        fi
    fi
    if echo "$url" | grep -qi "^https" && check_tool "testssl.sh"; then
        SSL=$(testssl.sh --quiet --severity MEDIUM "$domain" | grep -i "vulnerable")
        if [ -n "$SSL" ]; then
            print_result "High" "SSL vulns" "testssl: $SSL"
        fi
    fi
    if check_tool "wget"; then
        mkdir -p /tmp/vulnscan
        wget -q --spider -r -l 1 "$url" -P /tmp/vulnscan 2>/dev/null
        if find /tmp/vulnscan -name "*.env" -o -name "*.bak" | grep -q "."; then
            print_result "High" "Sensitive files" "Exposed .env or backups"
        fi
        rm -rf /tmp/vulnscan
    fi
}

# Main Loop
declare -a RESULTS
while true; do
    show_menu
    case $choice in
        1)
            read -p "Enter Web URL (e.g., https://example.com): " url
            web_scan "$url"
            ;;
        2)
            read -p "Enter App File Path (e.g., /path/to/app.apk): " file
            app_scan "$file"
            ;;
        3)
            read -p "Enter API URL (e.g., https://api.example.com): " url
            api_scan "$url"
            ;;
        4)
            read -p "Enter Target URL (e.g., https://example.com): " url
            full_scan "$url"
            ;;
        5)
            echo -e "${GREEN}Exiting... Stay secure!${NC}"
            break
            ;;
        *)
            echo -e "${RED}Invalid choice. Try again.${NC}"
            ;;
    esac

    if [ ${#RESULTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}Scan Summary${NC}"
        echo "------------------------------------------------"
        printf "%-8s | %-30s | %s\n" "Risk" "Issue" "Detail"
        echo "------------------------------------------------"
        for result in "${RESULTS[@]}"; do
            IFS='|' read -r risk issue detail <<< "$result"
            printf "%-8s | %-30s | %s\n" "$risk" "$issue" "$detail"
        done
        echo "------------------------------------------------"
    fi
    RESULTS=()
    echo -e "\nPress Enter to continue..."
    read
done

echo "Created by Cyber Defense Academy - Cybersecurity Done Right"
