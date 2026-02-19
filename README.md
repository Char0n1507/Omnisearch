# OmniScope

**The All-Seeing Subdomain Enumeration Tool**

OmniScope is a high-speed, comprehensive subdomain enumeration and reconnaissance tool designed for bug bounty hunters and penetration testers. It combines passive reconnaissance, active DNS verification, web probing, and visual reconnaissance into a unified workflow.

## 🚀 Features

*   **Passive Reconnaissance**: Aggregates subdomains from multiple sources:
    *   `crt.sh` (Certificate Transparency logs)
    *   `HackerTarget`
    *   `AlienVault OTX`
    *   `Anubis`
    *   `ThreatMiner`
    *   **Subfinder** integration for extended coverage
*   **Active Verification**: 
    *   High-concurrency DNS resolution (up to 2000 parallel checks)
    *   Wildcard DNS detection
*   **Web Probing**:
    *   Checks for HTTP/HTTPS services on live subdomains
    *   Captures Page Titles, Status Codes, and Server Headers
*   **Visual Reconnaissance**:
    *   **Aquatone** integration to take screenshots of all active web services
*   **Reporting**:
    *   Generates a clean HTML report (`report.html`) with all findings
    *   Saves raw results to `results.txt`
    *   Subdomain list for further processing

## 🛠️ Installation

### Prerequisites
*   Python 3.9+
*   Go (for external tools)
*   Chromium/Chrome (for Aquatone screenshots)

### Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Char0n1507/Omnisearch.git
    cd Omnisearch
    ```

2.  **Install Python dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install External Tools (Go)**:
    ```bash
    # Install Subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    # Install Aquatone (Download latest release)
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
    unzip aquatone_linux_amd64_1.7.0.zip
    sudo mv aquatone /usr/local/bin/  # Or ~/go/bin/
    ```

## 💻 Usage

Run the tool against a target domain:

```bash
python3 main.py -d target.com
```

### Options

*   `-d, --domain`: Target domain (e.g., `nasa.gov`)
*   `-w, --wordlist`: Path to a custom wordlist for brute-forcing (default: `wordlists/subdomains.txt`)
*   `-o, --output`: Output file for the raw subdomain list (default: `results.txt`)

## 📊 Output

After the scan completes, you will find:

*   **`report.html`**: A structured HTML table with links, status codes, titles, and server info.
*   **`aquatone_report/`**: A folder containing screenshots and a visual report of all web services.
*   **`results.txt`**: A plain text list of all valid, live subdomains found.

## 📝 License

This project is open-source and available under the MIT License.

---
*Created by Char0n1507*
