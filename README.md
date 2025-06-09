# 🛡️ Phishing Link Scanner

A Python-based tool to detect phishing-like characteristics in URLs by analyzing domain age, suspicious TLDs, HTTP response, and redirects.

---

## 🚀 Features

- 🧠 Scans for suspicious top-level domains (e.g., `.tk`, `.ml`, `.ga`)
- 📅 Checks domain registration age via WHOIS
- 🔁 Detects URL redirects
- 🌐 Verifies server HTTP status
- ✅ Provides verdict on URL safety

---

## 🛠️ Installation & Setup

### ✅ Step 1: Clone the Repository

git clone https://github.com/your-username/phishing-link-scanner.git
cd phishing-link-scanner

✅ Step 2: (Optional) Create a Virtual Environment
python3 -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate

✅ Step 3: Install Dependencies
pip install -r requirements.txt

🧪 Usage
✅ Step 4: Run the Script
python3 phishing_link_scanner.py

✅ Step 5: Enter the URL to scan when prompted
🔗 Enter the URL to scan: https://example.com

💡 Example Output
🔎 Scanning URL: https://example.com
[+] Server responded with status: 200
[!] Domain age: 512 days (safe)
[!] URL redirects 1 time(s) (common behavior)

✅ This URL looks safe based on current checks.

⚠️ Limitations
* WHOIS data may be restricted for some domains (due to privacy settings or rate-limiting)

* This tool is heuristic-based and not 100% accurate

* Use alongside browser protections and other cybersecurity tools
