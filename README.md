# ReconFlow

**ReconFlow** is a lightweight Python utility built for external attack surface management (EASM), pentest scoping, and baseline web security posture auditing. 

During initial reconnaissance and asset discovery, it is common to end up with dozens of scattered `.txt` files from separate tools. I built ReconFlow to automate passive subdomain enumeration, DNS/email security checks, HTTP probing, and defensive header analysis into a single workflow that outputs a clean, client-ready Markdown report.

> **Authorized Use & Educational Purpose Only**  
> This tool is developed strictly for authorized security assessments, defensive attack surface management, and educational research. You must have explicit permission from the asset owner before running active probes against any domain.
<img width="1147" height="531" alt="Screenshot_107" src="https://github.com/user-attachments/assets/d850ebdc-adb4-4dfa-9c19-9a4083286f56" />

---

## Key Features

- **Passive Subdomain Enumeration:** Queries Certificate Transparency (`crt.sh`) logs without sending noisy brute-force traffic to target DNS servers.
- **DNS & Email Spoofing Audit:** Resolves `A`, `CNAME`, and `MX` records while auditing root domains for missing or weak `SPF` and `DMARC` policies.
- **Dangling CNAME Visibility:** Highlights subdomains pointing to external `CNAME` targets that no longer resolve, helping teams spot potential subdomain takeover risks early.
- **Web & TLS Hygiene Probing:** Multithreaded HTTP/HTTPS probing that captures status codes, server banners, page titles, and remaining TLS certificate validity days.
- **Security Header Inspection:** Checks active web endpoints for missing defensive headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
- **Structured Markdown Reporting:** Exports findings and actionable remediation guidance directly to a formatted `.md` file (`examples/sample_report.md`).

---

## Project Structure
text
reconflow/
├── core/
│   ├── init.py
│   ├── ct_enum.py        # Certificate Transparency (crt.sh) parser
│   ├── dns_analyzer.py   # A/CNAME resolution & SPF/DMARC checks
│   ├── http_prober.py    # HTTP status, TLS expiry, and security headers
│   └── reporter.py       # Markdown report generator
├── examples/
│   └── sample_report.md  # Sample output report
├── reconflow.py          # Main CLI script
└── requirements.txt      # Python dependencies

---

## Installation

Clone the repository and install the required Python libraries:

git clone https://github.com/Mo-Pyshw/reconflow.git
cd reconflow
pip install -r requirements.txt


---

## Usage

Run an authorized posture audit against a domain and generate a Markdown report:

python3 reconflow.py -d example.com --authorized -o example_audit.md

---

## Sample Output

You can view a complete generated report in [`examples/sample_report.md`](examples/sample_report.md).

---

## License

Released under the [MIT License](LICENSE).
EOF

chmod +x reconflow.py
echo "[+] All 11 files created successfully inside ~/reconflow!"
