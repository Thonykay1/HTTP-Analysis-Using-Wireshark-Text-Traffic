# SBT-DF203 — Lab 4: SMTP Email Traffic Forensics

**Course:** Basic Networking Skills for Digital Forensics  
**Course Code:** SBT-DF203  
**Lab Number:** Lab 4  
**Lab Title:** SMTP Email Traffic Forensics  
**Delivery Block:** 2/3 of 3  
**Scheduled Dates:** 12–18 September 2026  
**Estimated Duration:** 3–4 hours practical work plus report writing  
**Mode:** Individual practical lab in an authorized isolated virtual environment  
**Prepared by:** Aminu Idris, AMCPN — Founder, ICDFA  
**Analyst:** Akinwa Omokunle Anthony 
**Analysis Workstation:** Kali Linux VM (isolated, host-only/NAT networking)

---

## 1. Objective

Analyze a historical SMTP packet capture (`smtp.pcap`) to:

- Identify when the email exchange occurred and the endpoints involved.
- Reconstruct SMTP commands, response codes, and authentication exchanges.
- Decode relevant Base64 authentication fields **offline** and in a controlled manner.
- Recover message headers and body content where the capture permits.
- Document the network path (IP/MAC addresses, ports) without unnecessarily exposing sensitive data.
- Assess evidential limitations when encryption (STARTTLS/SMTPS) or incomplete capture is present.

---

## 2. Legal, Ethical, and Safety Statement

This analysis was performed under the following constraints:

- All packet captures and systems used are authorized training materials supplied by ICDFA.
- Analysis was conducted in an **isolated virtual environment** with no connection to production, campus, office, or public networks.
- No real credentials, personal messages, or confidential traffic were collected or reused.
- The original capture was preserved; all analysis was performed on a verified working copy.
- SHA-256 hashes of the original and working copy were recorded to maintain evidence integrity.
- Any recovered usernames, passwords, or message content are treated as **confidential assessment evidence** and are masked in this public-facing document.

---

## 3. Environment and Tooling

| Item | Tool Used |
|---|---|
| Operating System | Kali Linux VM (VMware Workstation) |
| Packet Analysis | Wireshark, `tshark` |
| Decoding | Python 3 `base64` module (offline) |
| Hashing | `sha256sum` |
| Capture Metadata | `capinfos` |
| Evidence File | `smtp.pcap` (ICDFA-supplied sample) |
| Documentation | Local text editor |

---

## 4. Folder Structure
SBT-DF203-Lab4-SMTP-Forensics/
├── evidence/ # Original capture (hash-verified, read-only)
├── working/ # Analysis copy (never modify the original)
├── reports/ # tshark outputs, reconstructed email, hash records
├── screenshots/ # Wireshark and terminal evidence (Fig 1.x)
├── scripts/ # Offline Base64 decoder and helper scripts
├── exported/ # Optional exported artifacts (CSV, images)
└── README.md # This file

text

---

## 5. Evidence Integrity (Chain of Custody)

| Field | Value |
|---|---|
| Case/Lab Identifier | SBT-DF203-Lab4-AkinwaOmokunleAnthony |
| Evidence File | `evidence/smtp.pcap` |
| Source | ICDFA-supplied sample capture |
| Original SHA-256 | *(see `reports/smtp_capture_hashes.txt`)* |
| Working-Copy SHA-256 | *(see `reports/smtp_capture_hashes.txt`)* |
| Analysis Workstation | Kali Linux VM |
| Notes | Original preserved; analysis performed on `working/smtp_working.pcap` |

> Full hash values and the `capinfos` summary are stored in `reports/smtp_capture_hashes.txt` and `reports/smtp_capinfos.txt`.

---

## 6. Methodology Summary

The analysis follows the sequence defined in the SBT-DF203 lecture slides:

1. **Part A — Capture Inventory:** TCP conversation summary and SMTP packet inventory.
2. **Part B — Commands and Responses:** Extract SMTP commands (`EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`) and server response codes (`220`, `250`, `334`, `354`, `221`).
3. **Part C — Base64 Decoding:** Decode captured `AUTH LOGIN` credentials offline using Python's `base64` module. Full decoded values are retained only in a protected appendix; masked values appear in this report.
4. **Part D — Message Reconstruction:** Reassemble the SMTP TCP stream and separate RFC 5322 headers (`Date`, `From`, `To`, `Subject`, `Message-ID`, `MIME-Version`, `Content-Type`, `User-Agent`/`X-Mailer`) from the SMTP envelope.
5. **Part E — Network Metadata:** Extract MAC addresses, IP addresses, ports, and TCP stream identifiers; identify client software from `User-Agent`/`X-Mailer` headers.
6. **Part F — Encryption and Limitations:** Determine whether `STARTTLS` or implicit TLS is present and document what metadata remains visible in encrypted traffic.

---

## 7. Reports and Artifacts

| File | Description |
|---|---|
| `reports/tcp_conversations.txt` | TCP conversation summary (`tshark -z conv,tcp`) |
| `reports/smtp_packet_inventory.tsv` | SMTP frames with timestamps, endpoints, and info |
| `reports/smtp_commands_responses.tsv` | SMTP commands and server response codes |
| `reports/smtp_stream_<N>.txt` | Reassembled TCP stream for the SMTP session |
| `reports/message_headers.txt` | Extracted RFC 5322 headers |
| `reports/reconstructed_email_redacted.txt` | Redacted message reconstruction |
| `reports/smtp_network_metadata.tsv` | MAC/IP/port/stream metadata |
| `reports/client_indicators.tsv` | Client software indicators |
| `reports/smtp_capture_hashes.txt` | Original and working-copy SHA-256 hashes |
| `reports/smtp_capinfos.txt` | `capinfos` summary of the capture |

Screenshots referenced in the report are stored in `screenshots/` as `Fig 1.1` through `Fig 1.4` (folder structure, original hash, working-copy hash, `capinfos` summary).

---

## 8. Key Findings (Summary)

| Question | Finding |
|---|---|
| Session start / end | *(see Part B report)* |
| Client IP / MAC / port | *(see `smtp_network_metadata.tsv`)* |
| Server IP / MAC / port | *(see `smtp_network_metadata.tsv`)* |
| SMTP server banner | *(see Part B report)* |
| Client software | *(see `client_indicators.tsv`)* |
| Authentication method | *(see Part B report)* |
| Envelope sender / recipient | *(see Part B report)* |
| Message From / To / Subject | *(see `message_headers.txt`)* |
| Message body type | *(plain text / HTML / multipart)* |
| Attachment present | *(yes / no — see Part D report)* |
| STARTTLS / TLS observed | *(see Part F report)* |
| Key limitations | *(e.g., encrypted payload, missing frames)* |

---

## 9. Evidential Limitations

- Base64 is **encoding, not encryption** — recovered credentials demonstrate this distinction.
- If `STARTTLS` is negotiated, message content and credentials are **not recoverable** from the capture; only metadata (endpoints, ports, timing, byte counts, TLS handshake) remains visible.
- Port number alone does **not** prove encryption; protocol negotiation must be examined in the packet dissection.
- Incomplete captures may truncate the SMTP session; findings are limited to what was observed.

---

## 10. Ethical Handling of Recovered Credentials

As required by the lab instructions:

- Decoded credentials are treated as **confidential assessment evidence**.
- In this public-facing README and in the report body, credentials are **masked** (e.g., `analyst@example.com`, `P********3`).
- Full decoded values are retained only in a **protected appendix** if required by the instructor and are not published to this repository.

---

## 11. Reproducibility

All commands used in this analysis are documented in the corresponding `reports/*.txt` and `reports/*.tsv` files. Anyone with the original `smtp.pcap` can reproduce the analysis by following the SBT-DF203 Lab 4 procedure and running the same `tshark` filters.

---

## 12. References

- ICDFA SBT-DF203 — Basic Networking Skills for Digital Forensics, Lab 4: SMTP Email Traffic Forensics.
- RFC 5321 — Simple Mail Transfer Protocol.
- RFC 5322 — Internet Message Format.
- Wireshark Sample Captures — `smtp.pcap`.
- Wireshark Display Filter Reference — `smtp.*` fields.

---

*Prepared as part of the ICDFA SBT-DF203 three-week delivery block 2/3, 12–18 September 2026.*
