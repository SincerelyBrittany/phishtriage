# PhishTriage

[![CI](https://github.com/SincerelyBrittany/phishtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/SincerelyBrittany/phishtriage/actions/workflows/ci.yml)

A command-line tool that analyzes a suspicious email and tells you whether it's phishing, why, and what to do next.

Give it a raw email (`.eml`) and it checks sender authentication, pulls out links, domains, IPs and attachment hashes, looks them up in threat-intel services, and gives you a verdict (**Clean**, **Suspicious** or **Malicious**) with a plain-English explanation.

## Why I built it

I first analyzed phishing emails by hand for a security lab: reading headers, checking SPF/DKIM/DMARC, pulling out links and looking them up one at a time, then writing up a report. PhishTriage automates that same workflow so it takes seconds instead of a lab session, explains its verdict in plain English for non-technical people, and can run over a whole folder in a script.

## Results

| Sample (synthetic) | Expected | Result | Score |
| --- | --- | --- | --- |
| `fake_invoice.eml` | Malicious | Malicious | 100 |
| `credential_harvest.eml` | Malicious | Malicious | 55 |
| `html_attachment.eml` | Suspicious | Suspicious | 30 |
| `clean_newsletter.eml` | Clean | Clean | 5 |
| `clean_personal.eml` | Clean | Clean | 0 |

Offline mode, no API keys. 44 tests run in CI on Python 3.10, 3.11 and 3.12. The sample set is small, so this shows the rules behave as designed; measuring precision and recall on a larger labeled set is next.

## Features

- **Sender checks:** SPF, DKIM and DMARC results, and mismatched `From` / `Reply-To` / `Return-Path` addresses
- **Lookalike domains:** catches tricks like `paypa1.com`, `rnicrosoft.com` and `paypal.secure-login.example`
- **Deceptive links:** link text that shows one site but goes to another, raw-IP links, `@` tricks, URL shorteners
- **Risky attachments:** executables, double extensions (`invoice.pdf.exe`), HTML, ISO and macro files
- **Pressure language:** urgency and requests for passwords or payment
- **Threat intel:** VirusTotal and URLhaus lookups, cached to save your free API quota
- **Reports:** terminal summary, JSON or Markdown, with findings mapped to MITRE ATT&CK [T1566](https://attack.mitre.org/techniques/T1566/)

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/SincerelyBrittany/phishtriage.git
cd phishtriage
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Analyze one email
phishtriage analyze samples/fake_invoice.eml

# Without API keys / network access
phishtriage analyze samples/fake_invoice.eml --offline

# A whole folder, one JSON report per email
phishtriage analyze samples/ --format json --out reports/
```

| Option | Description |
| --- | --- |
| `--offline` | Skip threat-intel lookups |
| `--format`, `-f` | `text` (default), `json` or `md` |
| `--out`, `-o` | Write report files to a folder (`text` writes both `.json` and `.md`) |
| `--no-cache` | Don't use the lookup cache |
| `--max-lookups` | Max lookups per email per service (default 8) |

Exit codes: `0` clean, `1` suspicious, `2` malicious, `3` error. For a folder, the worst result wins, so you can use it in scripts.

### Example

```
╭─────────────────────────── PhishTriage ────────────────────────────╮
│ MALICIOUS  (score 100/100)                                         │
│ From: PayPal Billing <billing@paypa1.example>                      │
│ Subject: Invoice #INV-88213 overdue - action required              │
╰────────────────────────────────────────────────────────────────────╯
Summary  This email shows strong signs of phishing: it failed the check
that confirms who sent it (DMARC), the sender's address (paypa1.example)
imitates paypal by swapping characters and it was sent from a server
not allowed to send for that domain. Do not click any links, open
attachments or reply. Report it to your IT contact or email provider,
then delete it.

Key findings
  high    DMARC failed
  high    Lookalike sender domain: paypa1.example
  medium  SPF fail
  medium  Reply-To differs from From
  medium  Link text doesn't match destination
  ...
```

## API keys (optional)

Copy the example file and add your keys. Both services have free tiers.

```bash
cp .env.example .env
```

| Service | Used for | Variable |
| --- | --- | --- |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | URL, domain, IP and file hash reputation | `VT_API_KEY` |
| [URLhaus](https://urlhaus.abuse.ch/api/) | Known malicious URLs | `URLHAUS_AUTH_KEY` |

Without keys the tool still runs every header and content check and notes which lookups were skipped.

## Getting an email's `.eml` file

- **Gmail:** open the email → ⋮ menu → **Download message**.
- **Outlook (web):** open the email → ⋯ menu → **Save** / **Download**. In the desktop app, drag the email to a folder or use **File → Save As**.
- **Apple Mail:** select the email → **File → Save As…** → format **Raw Message Source**.

## Safety

- Attachments are hashed, never opened or saved.
- URLs are looked up, never visited.
- Your API keys stay in `.env`, which is git-ignored.

The files in `samples/` are synthetic. They use reserved `.example` domains and documentation IP ranges, so none of the links go anywhere real.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Design decisions

- **Treats every email as hostile.** Attachments are hashed in memory and never written to disk; URLs are looked up by ID, never visited. Only the topmost `Authentication-Results` header is trusted, because a sender can forge the ones below it.
- **Each check counts once.** Ten bad links don't drown out every other signal; the score reflects how many *kinds* of red flags an email has.
- **Weighted for real mail.** Return-Path mismatches and urgent wording score low, because legitimate newsletters and billing emails do both.
- **Free-tier friendly.** Lookups are cached for 24 hours, capped per email, and stop on rate limits.

See [docs/design.md](docs/design.md) for the full scoring table, threat model, failure log and known limitations.

## At scale

At 10,000× the volume (a company's whole reported-phish inbox), the single-process CLI would become a queue-fed service: workers parse and score in parallel, threat-intel lookups go through a shared cache with a paid API tier, and results feed a SIEM or ticketing system instead of the terminal. The checks themselves are already pure functions over a parsed email, so they'd move over unchanged.

## License

MIT. For educational and defensive use. Only analyze emails you're authorized to handle.
