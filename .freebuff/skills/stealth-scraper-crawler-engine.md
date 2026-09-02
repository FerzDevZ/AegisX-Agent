---
name: stealth-scraper-crawler-engine
description: >-
  Build robust web scrapers and crawlers with anti-bot bypass (Cloudflare Turnstile, DataDome),
  Playwright stealth plugin, rotating residential proxies, fingerprint masking, and rate-limit backpressure.
  Use when extracting data from complex websites, bypassing bot protections, or crawling multi-page SPAs.
---

# Stealth Scraper & Crawler Engine Master

This skill provides industry standards for scraping dynamic, JavaScript-heavy single-page applications while bypassing anti-bot challenges and maintaining high proxy throughput.

---

## 🕷️ Stealth Web Crawler Architecture

```mermaid
graph TD
    Target[Target Protected Website] --> ProxyPool[Residential Rotating Proxy Pool]
    ProxyPool --> StealthBrowser[Playwright Stealth Engine: Mask WebGL, Canvas, AudioContext]
    StealthBrowser --> Bypass[Automated Cloudflare Turnstile / CAPTCHA Solver]
    Bypass --> Extractor[Structured Data Extractor: Cheerio / BeautifulSoup / LLM Parser]
    Extractor --> DB[(Structured Output JSON / SQLite / PostgreSQL)]
```

---

## 🎯 Production Invariants

1. **Fingerprint Anonymization**: Never use standard Puppeteer/Playwright defaults without stripping `navigator.webdriver` and overriding `chrome.runtime`.
2. **Exponential Backoff on 429/403**: If a target endpoint returns HTTP 429 or 403, instantly rotate proxy IP and apply jittered delay.
3. **Structured Pydantic Extraction**: Parse extracted HTML directly into validated JSON schemas.

---

## 📋 Prosedur Eksekusi

1. **Cheatsheet Bypass & Fingerprinting**:
   - Baca [references/stealth-scraping-cheatsheet.md](./references/stealth-scraping-cheatsheet.md).
2. **Template Crawler**:
   - Rujuk [resources/stealth-crawler.py](./resources/stealth-crawler.py).
3. **Uji Koneksi Proxy**:
   - Jalankan `python3 skills/stealth-scraper-crawler-engine/scripts/test-proxy-connection.py`.