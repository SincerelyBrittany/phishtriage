# Design notes

## Pipeline

```
.eml -> parser -> extractor -> checks -> enrichment -> scoring -> report
```

| Stage | Module | Notes |
| --- | --- | --- |
| Parse | `parser.py` | stdlib `email`, 10 MB limit, attachments hashed (SHA-256) only |
| Extract | `extractor.py` | URLs from text and `href`s, domains, public IPs from `Received`, hashes |
| Check | `checks/` | auth, lookalike domains, deceptive links, attachment types, language |
| Enrich | `enrich/` | VirusTotal v3 + URLhaus, JSON cache with 24h TTL, per-email lookup cap |
| Score | `scoring.py` | weighted rules, each check counted once |
| Report | `report.py` | plain-English summary, terminal, JSON, Markdown (indicators defanged) |

## Threat model

The input is attacker-controlled, so the tool assumes every byte is hostile.

| Risk | Mitigation |
| --- | --- |
| Malicious attachment runs | Attachments are hashed in memory, never written to disk or opened |
| Tool visits a phishing URL | URLs are looked up by ID; nothing is fetched or submitted to a scanner |
| Huge or malformed email exhausts memory | 10 MB input cap, body truncation, parse errors caught |
| Terminal / Markdown injection via subject or links | Rich markup escaped; Markdown table pipes escaped; IOCs defanged |
| Forged `Authentication-Results` added by the sender | Only the topmost header (added by the receiving server) is trusted |
| API key leakage | Keys only from environment / `.env`, which is git-ignored |
| Free-tier quota exhaustion | Cache, lookup cap (default 8/service/email), stop on HTTP 429 |

## Scoring

Each check contributes once, at its highest severity, so ten bad links in one email
don't drown out every other signal. Total is capped at 100.

| Severity | Points | Examples |
| --- | --- | --- |
| critical | 40 | URL listed on URLhaus, indicator flagged by 2+ VirusTotal engines |
| high | 25 | DMARC fail, lookalike sender domain, executable or double-extension attachment |
| medium | 15 | SPF/DKIM fail, Reply-To mismatch, link text mismatch, raw-IP link, brand name in unrelated domain |
| low | 5 | SPF softfail, Return-Path mismatch, URL shortener, archive attachment, urgency or credential language |

| Score | Verdict |
| --- | --- |
| 0–19 | Clean |
| 20–49 | Suspicious |
| 50–100 | Malicious |

Why these choices:

- Return-Path mismatch is low because legitimate newsletters are sent through mailing services.
- Language checks are low because real billing and security emails use the same words.
- One threat-intel hit plus any other signal is enough for Malicious.

## Results on the sample set (offline mode)

| Sample | Expected | Result | Score |
| --- | --- | --- | --- |
| `fake_invoice.eml` | Malicious | Malicious | 100 |
| `credential_harvest.eml` | Suspicious | Suspicious | 45 |
| `html_attachment.eml` | Suspicious | Suspicious | 30 |
| `clean_newsletter.eml` | Clean | Clean | 5 |
| `clean_personal.eml` | Clean | Clean | 0 |

5/5 correct. The sample set is small and synthetic, so this checks the rules behave as
intended rather than measuring real-world precision and recall. Next step: label a larger
set of public phishing samples and legitimate mail and report precision/recall here.

## Known limitations

- Organizational domains use a small built-in suffix list, not the full Public Suffix List.
- The brand list for lookalike detection is short and hand-maintained.
- Plain-text emails can't be checked for link-text mismatches (there is no hidden `href`).
- Language checks are English only.
