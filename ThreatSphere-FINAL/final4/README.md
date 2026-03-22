# 🛡️ ThreatIntel Platform — SOC Intelligence Suite
Full-stack Node.js SOC platform · Zero npm dependencies · Mobile-responsive

## Quick Start

    node server/index.js
    # Open http://localhost:3000

Register → Sign in → Investigate. Works immediately with demo data.

## API Keys (all optional, all free)

Edit server/index.js:

    const KEYS = {
      virustotal : 'YOUR_KEY',   // virustotal.com/gui/my-apikey
      abuseipdb  : 'YOUR_KEY',   // abuseipdb.com/account/api
      shodan     : 'YOUR_KEY',   // account.shodan.io
      hybrid     : 'YOUR_KEY',   // hybrid-analysis.com/apikeys
      urlscan    : 'YOUR_KEY',   // urlscan.io/user/signup
      groq       : 'YOUR_KEY',   // console.groq.com (free AI)
    };

## What's in the tabs

VirusTotal: Detection bar + engine-by-engine results table + file metadata (MD5/SHA1/SHA256, size, type) + community votes + threat classification + ASN/country

Hybrid Analysis: Sandbox reports, malware family, threat score. Shows helpful setup message when no key configured.

WHOIS: Registration data with age-based risk indicators, nameservers, domain status. Rich demo data when offline.

Notes: Priority quick-tags (Confirmed Malicious, False Positive, Ticket, etc.), Ctrl+Enter to save, Ctrl+K to focus.

Recent Investigations: Rich mini-cards with risk bar, verdict chip, relative time, notes badge.

## Advanced Features

Threat Feeds: 8 free sources (Feodo Tracker, URLhaus, ThreatFox, MalwareBazaar, Emerging Threats, OpenPhish, SSL Blacklist, CINS Score). Search + filter + copy + investigate buttons. Demo data when offline.

Sandbox: Safe files (PDF/JPG/XLSX/MP3/ZIP) always clean. Executables/scripts analysed by hash. Shows processes, C2 network calls, registry changes, MITRE TTPs. C2 IPs only appear for truly malicious files.

Hash Calculator: Client-side MD5/SHA-1/SHA-256/SHA-512. File never leaves browser. Quick links to VT/MalwareBazaar.

Relationship Graph: Force-directed SVG graph showing IP/domain/hash relationships. Click any node to pivot.

## Hosting (not Netlify — static only)

Railway: railway up (500 hrs/month free)
Render: Connect GitHub repo
Fly.io: fly launch (3 free VMs)
Any VPS: node server/index.js

## Requirements

Node.js 16+. No npm install needed.
