# Reachable

Real-time email deliverability diagnostics for any domain or IP.

Reachable checks the technical infrastructure behind your email sending. SPF, DKIM, DMARC, blacklists, reverse DNS, and more. It tells you exactly what is wrong and how to fix it. No sign-up. No backend. Runs entirely in your browser.

Live at: **[reachable.info](https://reachable.info)**

---

## What it does

### Domain Audit
- SPF record validation (lookup count, all mechanism, multiple record detection)
- DMARC policy analysis (p=, sp=, pct=, rua= coverage)
- DKIM public key verification with key size estimation
- MX record check
- BIMI record detection
- MTA-STS / TLS policy check
- Domain blacklist checks (URIBL, SURBL, DBL Spamhaus)
- Return-path / bounce domain SPF alignment

### IP Checks
- Reverse DNS (PTR) lookup with forward-confirmation
- IP blacklist checks across 5 major DNSBLs (Spamhaus ZEN, Barracuda, SORBS, SpamCop, MXToolbox)

### Header Analyzer
- Paste raw email headers to decode SPF / DKIM / DMARC / ARC results in transit
- Routing path visualization (hop by hop)
- Spam signals and flags
- Key header extraction (From, Return-Path, Message-ID, X-Mailer)

### DNS Simulator
- Paste a proposed SPF or DMARC record before publishing it
- Validates structure, estimates DNS lookup count against the 10-lookup SPF limit
- Flags dangerous configurations like +all, missing all mechanism, low pct=
- No DNS changes are made, analysis only

---

## How it works

All checks run in the browser using Cloudflare DNS-over-HTTPS. No data is sent to any server. No analytics. No tracking.

DNS lookups go to: `https://cloudflare-dns.com/dns-query`

Blacklist checks use standard DNSBL reverse-IP queries against public blocklists.

---

## Stack

- Vanilla HTML, CSS, JavaScript
- No frameworks, no dependencies, no build step
- Single file deployment

---

## Running locally

Just open `index.html` in a browser. For local development with CORS support:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`

---

## Built by

[Tarul Khantwal](https://www.linkedin.com/in/tarulkhantwal) · MarTech Specialist
