"""
OpSec & Cyber Threat Intelligence Automated Pipeline.
Developed for zero-footprint OSINT gathering, bypassing WAFs via TLS impersonation,
and semantic analysis utilizing Large Language Models.
"""

import os
import time
import random
import logging
from typing import Optional, List
from urllib.parse import urljoin

import feedparser
import requests
from bs4 import BeautifulSoup
from groq import Groq
from curl_cffi import requests as tls_requests
import trafilatura

# ==========================================
# 1. Configuration & Global Constants
# ==========================================

# Configure Enterprise-Grade Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# API Keys & Secrets
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

DB_FILE = "data/sent_urls.txt"
os.makedirs("data", exist_ok=True)

# Intelligence Sources (RSS Feeds)
RSS_FEEDS: List[str] = [
    "https://www.privacyguides.org/articles/feed_rss_created.xml",
    "https://www.bleepingcomputer.com/rss-feeds/",
    "https://krebsonsecurity.com/feed",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://cryptostorm.is/blog/rss.xml",
    "https://ooni.org/blog/index.xml",
    "https://blog.torproject.org/feed",
    "https://guardianproject.info/feed.xml",
    "https://www.eff.org/rss",
    "https://proton.me/blog/feed",
    "https://forbiddenstories.org/feed"
]

# Intelligence Sources (Custom Web Scraping via CSS Selectors)
CUSTOM_SITES: List[dict] = [
    {"name": "Dark Reading", "url": "https://www.darkreading.com/", "selector": "a.article-title-link"},
    {"name": "CyberNews", "url": "https://cybernews.com/", "selector": "h3.article__title a"},
    {"name": "No Trace Project", "url": "https://notrace.how/resources/", "selector": "ul.resource-list li a"},
    {"name": "Tuta Blog", "url": "https://tuta.com/blog", "selector": "li h3 a, h3 a"},
    {"name": "7ASecurity", "url": "https://7asecurity.com/blog", "selector": "article h3 a, h3 a"},
    {"name": "Censored Planet", "url": "https://censoredplanet.org/", "selector": "h3 a, div.post-item a"},
    {"name": "Access Now", "url": "https://www.accessnow.org/", "selector": "h3.entry-title a, .post a"},
    {"name": "Open Technology Fund", "url": "https://www.opentech.fund/news/", "selector": "h3.article-title a, .post-content a"}
]

# Initialize LLM Client
client = Groq(api_key=GROQ_API_KEY)

# ==========================================
# 2. State Management
# ==========================================

def load_sent_urls() -> set:
    """Loads previously processed URLs from the local database file."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return set(f.read().splitlines())
    return set()

def save_sent_urls(new_urls: List[str]) -> None:
    """Appends newly processed URLs to the database."""
    if new_urls:
        with open(DB_FILE, "a", encoding="utf-8") as f:
            for link in new_urls:
                f.write(link + "\n")

# ==========================================
# 3. Core Functions
# ==========================================

def send_to_telegram(text: str) -> None:
    """Dispatches the formatted intelligence report to a Telegram channel/chat."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Telegram dispatch failed: {e}")

def fetch_full_article(url: str) -> Optional[str]:
    """
    Executes a zero-footprint web scrape utilizing dynamic TLS impersonation
    to bypass WAFs (e.g., Cloudflare, Datadome).
    """
    # Rotate browser fingerprints dynamically to evade heuristic detection
    browsers = ["chrome110", "chrome116", "chrome120", "edge101", "safari15_3"]
    target_browser = random.choice(browsers)
    
    try:
        response = tls_requests.get(url, impersonate=target_browser, timeout=15)
        if response.status_code == 200:
            text = trafilatura.extract(response.text)
            if text:
                # Semantic Chunking: Cap at 6000 chars, ensuring truncation happens at a full stop
                truncated = text[:6000]
                if len(text) > 6000:
                    truncated = truncated.rsplit('.', 1)[0] + '.'
                return truncated
    except Exception as e:
        logging.warning(f"Content extraction failed for {url} (Impersonating {target_browser}) - {e}")
    return None

def process_and_send_article(article_url: str, article_title: str, sent_urls: set, fallback_text: str = "") -> bool:
    """
    Orchestrates the pipeline: Check State -> Scrape -> LLM Analysis -> Telegram Dispatch -> OpSec Jitter.
    """
    if article_url in sent_urls:
        return False
        
    full_text = fetch_full_article(article_url)
    
    if full_text:
        article_content = full_text
        logging.info(f"Successfully extracted full payload: {article_title}")
    else:
        if not fallback_text:
            logging.info(f"Skipped (No payload available): {article_title}")
            return False
        article_content = fallback_text
        logging.info(f"Fell back to summary snippet for: {article_title}")
    
    # Refined CTI Prompt: Clean Professional Style
    prompt = f"""
    ### ROLE:
    Act as a Senior Cyber Threat Intelligence (CTI) Specialist. 

    ### INSTRUCTIONS:
    1. **Language:** Professional Technical English.
    2. **Formatting:** Use ONLY HTML tags (<b>, <i>) for styling. 
    3. **STRICT RULE:** NO Markdown symbols (like **, *, or ***). Use bullet points (•) for lists.
    4. **Tone:** Tactical and authoritative.

    ### INPUT DATA:
    - Title: {article_title}
    - Content: {article_content}

    ### REQUIRED OUTPUT FORMAT:
    🛡️ <b>Tactical Intelligence Report</b>

    🎯 <b>Executive Summary:</b>
    (A high-level overview. Max 2 sentences.)

    🔍 <b>Technical Analysis & Impact:</b>
    • <b>Vector:</b> (e.g., RCE, Phishing)
    • <b>Affected:</b> (Affected systems or CVE IDs)
    • <b>Key Findings:</b>
      • (Technical Detail 1)
      • (Technical Detail 2)
      • (Technical Detail 3)

    🛠️ <b>Remediation & Strategy:</b>
    (Provide technical steps for defense.)

    ---
    <i>Generated by Sentinel-OSINT-Pipeline | Tactical Grade Intel</i>

    """
    
    try:
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="openai/gpt-oss-120b",
            temperature=0.3,
            max_completion_tokens=2048,
            top_p=1,
            reasoning_effort="medium"
        )
        analysis = chat_completion.choices[0].message.content
        final_text = f"🚨 <b>{article_title}</b>\n\n{analysis}\n\n🔗 <a href='{article_url}'>Source Reference</a>"
        
        send_to_telegram(final_text)
        sent_urls.add(article_url)
        logging.info(f"Dispatched report for: {article_title}")
        
        # OpSec Jittering: Obfuscate automated request patterns
        sleep_time = random.uniform(22.0, 35.0)
        logging.info(f"Initiating traffic obfuscation jitter: sleeping for {sleep_time:.2f} seconds...")
        time.sleep(sleep_time)
        return True

    except Exception as e:
        logging.error(f"LLM processing failed for {article_title}: {e}")
        return False

# ==========================================
# 4. Main Execution Logic
# ==========================================

def main():
    logging.info("Initializing OpSec Intelligence Pipeline...")
    sent_urls = load_sent_urls()
    new_links_processed = []

    # Phase 1: Process Standard RSS Feeds
    logging.info("Phase 1: Scanning standardized RSS feeds...")
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:3]:
                if entry.link not in sent_urls:
                    success = process_and_send_article(
                        article_url=entry.link, 
                        article_title=entry.title, 
                        sent_urls=sent_urls,
                        fallback_text=entry.get('summary', entry.get('description', ''))
                    )
                    if success:
                        new_links_processed.append(entry.link)
        except Exception as e:
            logging.error(f"RSS Parsing failed for {url}: {e}")

    # Phase 2: Process Custom Scraping Targets
    logging.info("Phase 2: Initiating targeted web scraping (No-RSS sites)...")
    main_page_browsers = ["chrome110", "chrome116", "edge101"]

    for site in CUSTOM_SITES:
        try:
            target_browser = random.choice(main_page_browsers)
            response = tls_requests.get(site["url"], impersonate=target_browser, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'lxml')
                
                # Parse multiple selectors if provided (comma-separated)
                selectors = [s.strip() for s in site["selector"].split(",")]
                articles = []
                for selector in selectors:
                    articles.extend(soup.select(selector))
                    if articles: 
                        break
                        
                articles = articles[:3] # Limit to latest 3 articles
                
                for article in articles:
                    raw_link = article.get('href')
                    if not raw_link:
                        continue
                    full_link = urljoin(site["url"], raw_link)
                    title = article.get_text(strip=True) or "Intelligence Update"
                    
                    if full_link not in sent_urls:
                        success = process_and_send_article(
                            article_url=full_link, 
                            article_title=title,
                            sent_urls=sent_urls
                        )
                        if success:
                            new_links_processed.append(full_link)
        except Exception as e:
            logging.error(f"Targeted scraping failed for {site['name']}: {e}")

    # Phase 3: State Persistence
    if new_links_processed:
        save_sent_urls(new_links_processed)
        logging.info(f"Pipeline execution complete. Persisted {len(new_links_processed)} new records.")
    else:
        logging.info("Pipeline execution complete. No new intelligence detected.")

if __name__ == "__main__":
    main()
