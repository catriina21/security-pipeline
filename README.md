#  DevSecOps Automated Security Scanner Pipeline (Local Engine)

Sistem pengujian keamanan aplikasi web otomatis berbasis *Local-First Engine* yang dirancang untuk audit pra-rilis (*pre-release/staging check*). 

Pipeline ini mengombinasikan berbagai *tools* analisis keamanan industri yang dipetakan langsung ke standar **OWASP Top 10 Framework** serta metode penilaian mutu berbasis **Mozilla HTTP Observatory Metric**.

---

###  Fitur & Modul Utama
- **Validation & Reconnaissance:** Identifikasi status HTTP, DNS Record, dan WHOIS.
- **Port & Service Scanning:** Pemindaian *port* aktif menggunakan Nmap.
- **Sensitive Endpoint Audit:** Pemeriksaan 50+ jalur sensitif (`.env`, `.git`, `.sql`, dll) dilengkapi engine **Anti-Soft 404 Triaging**.
- **Web Vulnerability Audit:** Pemindaian miskonfigurasi server & *directory brute-forcing* (Nikto & Gobuster).
- **Advanced Vulnerability Audit:** Integrasi pemindai berbasis *template* (Nuclei, Dalfox, Trivy) dengan *safe-skip mechanism*.
- **Executive Visual Dashboard:** Output laporan HTML lokal yang *print-friendly* (siap diekspor ke PDF) dengan indikator *Security Grade* (A–F).

---

###  Cara Penggunaan di Laptop Mentor / Evaluator

#### 1. Clone Repositori
Buka terminal WSL / Ubuntu, lalu unduh repositori ini:
```bash
git clone [https://github.com/catriina21/security-pipeline.git](https://github.com/catriina21/security-pipeline.git)
cd security-pipeline

### 2. Instalasi Dependensi Otomatis (Cukup 1x di awal)
Eksekusi skrip setup.sh untuk mengunduh seluruh utilitas pendukung secara otomatis:
Bash
chmod +x setup.sh local_scan.sh
./setup.sh

#### 3. Jalankan Pemindaian Keamanan
Jalankan pipeline dengan memasukkan URL target dan mode kedalaman audit (quick / full):
Bash
./local_scan.sh [https://bekasikota.go.id](https://bekasikota.go.id) quick
 
