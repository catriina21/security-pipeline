#!/bin/bash

echo "================================================================"
echo " 🛠️ PREPARING LOCAL DEVSECOPS PIPELINE ENVIRONMENT"
echo "================================================================"

# 1. Update repository & install seluruh utilitas Linux yang dibutuhkan
echo "[+] Updating apt repositories & installing core packages..."
sudo apt update && sudo apt install -y \
    curl \
    nmap \
    nikto \
    gobuster \
    whois \
    dnsutils \
    python3 \
    unzip \
    wget \
    git

# 2. Buat struktur folder proyek jika belum ada
echo "[+] Ensuring project directory structure exists..."
mkdir -p config scripts security-reports/raw_logs

# 3. Buat berkas konfigurasi sensitive_paths.txt jika belum ada
if [ ! -f "config/sensitive_paths.txt" ]; then
    echo "[+] Generating default config/sensitive_paths.txt..."
    cat << 'PATHS' > config/sensitive_paths.txt
/.env
/.git/config
/.git/HEAD
/wp-config.php.bak
/config.php.bak
/config.json
/settings.py
/database.yml
/backup.sql
/db.sql
/dump.sql
/backup.zip
/backup.tar.gz
/admin/
/administrator/
/login/
/dashboard/
/api/
/v1/
/v2/
/swagger.json
/swagger-ui.html
/api-docs
/graphql
/phpmyadmin/
/pma/
/server-status
/server-info
/.htaccess
/.htpasswd
/robots.txt
/sitemap.xml
/crossdomain.xml
/elmah.axd
/trace.axd
/info.php
/phpinfo.php
/test.php
/.well-known/security.txt
/Jenkinsfile
/.github/workflows/
/docker-compose.yml
/Dockerfile
/package-lock.json
/yarn.lock
PATHS
fi

# 4. Beri hak akses eksekusi pada skrip runner
echo "[+] Setting execution permissions..."
chmod +x local_scan.sh setup.sh 2>/dev/null || true

echo "================================================================"
echo " ✅ SETUP SELESAI!"
echo " 🚀 Jalankan scanner: ./local_scan.sh <TARGET_URL> quick"
echo "================================================================"
