# SecurityOps 101

A beginner-friendly, hands-on cybersecurity lab built as a static website.

**Live demo:** https://227x0.github.io/cybersec-lab/

## Labs

1. **SOC Alert Triage Simulator** — decide whether to escalate or dismiss alerts like an L1 analyst.
2. **Email Header Analyzer** — paste raw headers and spot SPF/DKIM/DMARC issues and spoofing signs.
3. **IOC Lookup Trainer** — practice reading verdicts for IPs, domains, hashes, and URLs.
4. **MITRE ATT&CK Mapper** — map alert scenarios to the right MITRE technique.
5. **Case File** — end-to-end incident response case with logs, IOCs, and a verdict exercise.
6. **Password Lab** — type a password and see a real-time strength estimate with an offline crack-time approximation.
7. **Phishing Lab** — inspect a suspicious email, click the red flags, and learn why each one matters.
8. **Permissions Lab** — toggle Linux `rwx` bits and instantly see the numeric mode, symbolic mode, and access outcome.

## Why this project?

Most beginner cybersec content is either too theoretical or a full CTF that throws you in the deep end. This lab focuses on the small, practical things that actually protect real users and systems every day.

## Tech stack

- Pure HTML, CSS, and vanilla JavaScript
- No build step, no external APIs, no tracking
- Deployed on GitHub Pages

## Run locally

```bash
git clone https://github.com/227x0/cybersec-lab.git
cd cybersec-lab
# open index.html in any browser, or:
python -m http.server 8000
```

## License

MIT
