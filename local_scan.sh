#!/bin/bash

# Configuration & Variables
TARGET_URL="${1:-http://localhost}"
SCAN_DEPTH="${2:-quick}"
RAW_LOGS="security-reports/raw_logs"

mkdir -p "$RAW_LOGS"

echo "================================================================"
echo " 🛡️ LOCAL DEVSECOPS SECURITY SCANNER"
echo " Target: $TARGET_URL | Depth Mode: $SCAN_DEPTH"
echo "================================================================"

# JOB 1: CHECK CONNECTIVITY
echo -e "\n[+] JOB 1: Validasi Konektivitas Target..."
HTTP_CODE=$(curl -s -k -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -o /dev/null -w "%{http_code}" --connect-timeout 10 "$TARGET_URL")

if [ "$HTTP_CODE" -eq 000 ]; then
    echo "❌ Error: Tidak dapat terhubung ke $TARGET_URL. Pemindaian dibatalkan."
    exit 1
fi
echo "  [✓] Target Aktif (Status Code: $HTTP_CODE)"

# JOB 2: RECON & HEADERS SCAN
echo -e "\n[+] JOB 2: Mengambil HTTP Response Headers..."
curl -s -I -k -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "$TARGET_URL" > "$RAW_LOGS/headers.txt"
echo "  [✓] Log Headers Disimpan: $RAW_LOGS/headers.txt"

# JOB 3: NMAP PORT SCAN
echo -e "\n[+] JOB 3: Pemindaian Port Nmap..."
DOMAIN=$(echo "$TARGET_URL" | sed -e 's|^[^:]*://||' -e 's|/.*||' -e 's|:.*||')
if [ "$SCAN_DEPTH" == "full" ]; then
    nmap -sV -p 21,22,80,443,8080,8443 "$DOMAIN" -oN "$RAW_LOGS/nmap.txt" > /dev/null 2>&1 || true
else
    nmap -F "$DOMAIN" -oN "$RAW_LOGS/nmap.txt" > /dev/null 2>&1 || true
fi
echo "  [✓] Log Nmap Disimpan: $RAW_LOGS/nmap.txt"

# JOB 4: SENSITIVE PATH CHECK (BASELINE COMPARISON ENGINE)
echo -e "\n[+] JOB 4: Audit Path Sensitif (Baseline Anti-Soft 404)..."
SENSITIVE_LOG="$RAW_LOGS/sensitive_check.txt"
echo "Path Check Results for $TARGET_URL" > "$SENSITIVE_LOG"

RANDOM_PATH="/random_test_path_$(date +%s)_404"
BASELINE_URL="${TARGET_URL%/}$RANDOM_PATH"
BASELINE_SIZE=$(curl -s -k -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --connect-timeout 5 "$BASELINE_URL" | wc -c)
echo "  [*] Baseline Response Size (Custom 404 Page): $BASELINE_SIZE bytes"

if [ -f "config/sensitive_paths.txt" ]; then
    while IFS= read -r path || [ -n "$path" ]; do
        [ -z "$path" ] && continue
        FULL_URL="${TARGET_URL%/}$path"
        
        RESPONSE=$(curl -s -k -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --connect-timeout 3 "$FULL_URL")
        CODE=$(curl -s -k -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -o /dev/null -w "%{http_code}" --connect-timeout 3 "$FULL_URL")
        CURRENT_SIZE=$(echo -n "$RESPONSE" | wc -c)

        if [ "$CODE" -eq 200 ]; then
            SIZE_DIFF=$(( CURRENT_SIZE - BASELINE_SIZE ))
            SIZE_DIFF=${SIZE_DIFF#-}

            if [ "$SIZE_DIFF" -le 100 ] || echo "$RESPONSE" | grep -iqE "not found|tidak ditemukan|404 page|page not found|halaman tidak ditemukan|beranda|home|kembali|oops|maaf"; then
                echo "  [ℹ️] SOFT 404 DETECTED (Ignored): $FULL_URL"
            else
                echo "  [⚠️] EXPOSED (200 OK): $FULL_URL" | tee -a "$SENSITIVE_LOG"
            fi
        fi
    done < config/sensitive_paths.txt
fi

# JOB 5: WEB VULNERABILITY SCAN (NIKTO & GOBUSTER)
echo -e "\n[+] JOB 5: Pemindaian Nikto & Gobuster..."
if command -v nikto >/dev/null 2>&1; then
    if [ "$SCAN_DEPTH" == "full" ]; then
        nikto -h "$TARGET_URL" -output "$RAW_LOGS/nikto.txt" > /dev/null 2>&1 || true
    else
        nikto -h "$TARGET_URL" -Tuning 123b -output "$RAW_LOGS/nikto.txt" > /dev/null 2>&1 || true
    fi
    echo "  [✓] Log Nikto Disimpan"
else
    echo "  [!] Nikto tidak ditemukan, melewatinya..."
fi

if command -v gobuster >/dev/null 2>&1 && [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
    gobuster dir -u "$TARGET_URL" -w /usr/share/wordlists/dirb/common.txt -q -o "$RAW_LOGS/gobuster.txt" > /dev/null 2>&1 || true
    echo "  [✓] Log Gobuster Disimpan"
else
    echo "  [!] Gobuster atau Wordlist tidak ditemukan, melewatinya..."
fi

# JOB 6: ADVANCED TOOL RUNNER (NUCLEI, DALFOX & TRIVY)
echo -e "\n[+] JOB 6: Pemindaian Alat Keamanan Lanjutan (Nuclei, Dalfox & Trivy)..."

if command -v nuclei >/dev/null 2>&1; then
    echo "  [+] Jalankan Nuclei Template Scan..."
    nuclei -u "$TARGET_URL" -severity low,medium,high,critical -o "$RAW_LOGS/nuclei.txt" > /dev/null 2>&1 || true
    echo "  [✓] Log Nuclei Disimpan: $RAW_LOGS/nuclei.txt"
else
    echo "  [ℹ️] Tool 'nuclei' tidak terpasang. Melompati..."
fi

if command -v dalfox >/dev/null 2>&1; then
    echo "  [+] Jalankan Dalfox XSS Scanner..."
    dalfox url "$TARGET_URL" -o "$RAW_LOGS/dalfox.txt" > /dev/null 2>&1 || true
    echo "  [✓] Log Dalfox Disimpan: $RAW_LOGS/dalfox.txt"
else
    echo "  [ℹ️] Tool 'dalfox' tidak terpasang. Melompati..."
fi

if command -v trivy >/dev/null 2>&1; then
    echo "  [+] Jalankan Trivy FS / Repo Scan..."
    trivy fs . --format table -o "$RAW_LOGS/trivy.txt" > /dev/null 2>&1 || true
    echo "  [✓] Log Trivy Disimpan: $RAW_LOGS/trivy.txt"
else
    echo "  [ℹ️] Tool 'trivy' tidak terpasang. Melompati..."
fi

# JOB 7 & 8: TRIAGE ENGINE & HTML DASHBOARD
echo -e "\n[+] JOB 7 & 8: Memproses Triage Engine & Membuat Laporan HTML Visual..."
python3 scripts/generate_html_report.py "$TARGET_URL"

# EXECUTIVE TERMINAL SUMMARY
PORTS_COUNT=$(grep -c "/tcp.*open" "$RAW_LOGS/nmap.txt" 2>/dev/null || echo "0")
EXPOSED_COUNT=$(grep -c "EXPOSED" "$RAW_LOGS/sensitive_check.txt" 2>/dev/null || echo "0")

echo -e "\n================================================================"
echo " 📊 EXECUTIVE SUMMARY (CLI REPORT)"
echo "================================================================"
echo " 🎯 Target URL         : $TARGET_URL"
echo " 🔌 Total Open Ports   : $PORTS_COUNT Port"
echo " ⚠️ Exposed Paths Found : $EXPOSED_COUNT Endpoint"
echo "================================================================"
echo " 🎉 PROSES SCANNING & AUDIT SELESAI!"
echo " 📄 Laporan Visual HTML : security-reports/SECURITY-AUDIT-REPORT.html"
echo "================================================================"
