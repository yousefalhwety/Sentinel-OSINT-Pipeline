# 🛡️ Sentinel-OSINT-Pipeline

## 📖 Overview
This project is an advanced, decentralized Open Source Intelligence (OSINT) pipeline. It autonomously aggregates, filters, and semantically analyzes cybersecurity news, zero-day vulnerability reports, and operational security (OpSec) guides from high-profile, WAF-protected sources. The system is engineered to provide actionable intelligence with minimal human intervention.

## 🏗️ Architecture & Tech Stack
- **Execution Engine:** Stateless, scheduled operations orchestrated via **GitHub Actions** (Cron-triggered).
- **Evasion & Extraction:** - `curl_cffi`: Implements **Dynamic TLS/JA3 fingerprint impersonation** to bypass advanced Web Application Firewalls (WAFs) like Cloudflare and Datadome.
  - `trafilatura`: Utilized for high-fidelity, text-only content extraction, stripping away DOM noise, ads, and trackers.
  - `BeautifulSoup4`: Employed for precision-targeted scraping on non-RSS enabled platforms using custom CSS selectors.
- **AI/LLM Analysis:** Integrated with **GPT-OSS 120B** (via Groq API) for semantic processing, deduplication, and generating structured technical intelligence reports in localized formats.
- **State Persistence:** Git-backed persistent state management within the `data/` directory, isolated from the core logic to ensure 100% serverless operation.
- **OpSec Hardening:** Implements execution jittering (randomized distribution intervals) to obfuscate automated traffic patterns and evade heuristic bot detection.

## 🚀 Quick Start (Deployment)
To deploy your own instance of this pipeline:
1. **Fork** this repository.
2. Navigate to **Settings > Secrets and variables > Actions** and add the following Secrets:
   - `GROQ_API_KEY`: Get your free API key from the [Groq Console](https://console.groq.com/keys).
   - `TELEGRAM_BOT_TOKEN`: Create a new bot via [@BotFather](https://t.me/botfather) on Telegram and copy the generated token.
   - `TELEGRAM_CHAT_ID`: Send a message to [@userinfobot](https://t.me/userinfobot) on Telegram to retrieve your numeric Chat ID.
3. Enable **GitHub Actions** in the `Actions` tab.
4. (Optional) Trigger the workflow manually to verify the setup.

## 📂 Project Structure
```text
├── .github/workflows/
│   └── bot.yml            # CI/CD orchestration & automation logic
├── data/
│   ├── sent_urls.txt      # Persistent state: tracks processed intelligence
│   └── keepalive.txt      # System heartbeat to maintain runner activity
├── opsec_news.py          # Core Python intelligence & analysis engine
├── requirements.txt       # Project dependency manifest
└── .gitignore             # Operational security exclusions
```

## 🔒 Security & Disclosure Note
This public repository provides the **core engine and architecture** of the pipeline. To maintain the integrity of private monitoring operations, specific high-value intelligence sources and detailed historical execution logs are maintained in a separate, private production environment. This ensures long-term persistence against evolving anti-bot countermeasures while sharing the tool's capabilities with the community.

---
*Developed for professional-grade security research and automated threat monitoring.*
