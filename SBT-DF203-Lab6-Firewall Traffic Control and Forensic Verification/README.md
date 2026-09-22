# SBT-DF203 — Lab 6: Firewall Traffic Control and Forensic Verification

**Course:** Basic Networking Skills for Digital Forensics  
**Course Code:** SBT-DF203  
**Lab Number:** Lab 6  
**Lab Title:** Firewall Traffic Control and Forensic Verification    
**Scheduled Dates:** 12–18 September 2026  
**Estimated Duration:** 4–5 hours practical work plus report writing  
**Mode:** Individual practical lab in an authorized isolated virtual environment  
**Prepared by:** Aminu Idris, AMCPN — Founder, ICDFA  
**Analyst:** Akinwa Omokunle Anthony  
**Analysis Workstation:** Kali Linux VM (isolated, host-only/NAT networking)

---

## 1. Objective

Validate a Linux host-based firewall's ability to control HTTP traffic from one authorized client while allowing another, by:

- Documenting baseline HTTP access before any firewall change.
- Applying a narrowly scoped `iptables` INPUT rule that blocks HTTP from one assigned client IP.
- Capturing allowed and blocked HTTP traffic with `tshark`.
- Correlating packet evidence with firewall rule counters and client-side `curl` behaviour.
- Explaining the difference between `DROP` and `REJECT` and interpreting retransmission/timeout evidence.
- Restoring the original firewall ruleset safely and documenting the restoration.

---

## 2. Legal, Ethical, and Safety Statement

This analysis was performed under the following constraints:

- All systems, captures, and networks used are authorized ICDFA lab resources.
- Analysis was conducted in an **isolated host-only/internal virtual network** with no connection to production, campus, office, or public networks.
- No real credentials, personal messages, or confidential traffic were collected or reused.
- The original firewall ruleset was exported and hashed **before** any change, providing a safe rollback point.
- Only a single, source-specific rule was applied to the assigned lab IP; no firewall flush was performed.
- The blocking rule was removed after evidence collection, and the INPUT chain was confirmed restored to its baseline state.

---

## 3. Environment and Tooling

| Item | Tool Used |
|---|---|
| Operating System | Kali Linux VM (VMware Workstation) |
| Protected Host / Server | Kali `192.168.186.128`, interface `eth0`, Apache 2.4.68 (Debian) |
| Requesting Client | Windows VM `192.168.186.1` (VMnet8, NAT, isolated) |
| Firewall | `iptables` 1.8.13 (nf_tables), `iptables-save`, `iptables-restore` |
| Packet Analysis | Wireshark, `tshark` |
| Client Tool | `curl` (Windows) |
| Hashing | `sha256sum` |
| Capture Metadata | `capinfos` |
| Documentation | Local text editor |

---

## 4. Folder Structure
SBT-DF203-Lab6/
├── evidence/ # Original captures and firewall ruleset (hash-verified)
├── working/ # Analysis copy (never modify the original)
├── reports/ # tshark outputs, rule exports, hashes, comparisons
├── screenshots/ # Wireshark and terminal evidence (Fig X.Y)
├── scripts/ # Optional helper scripts
├── exported/ # Optional exported artifacts (CSV, images)
└── README.md # This file

text

---

## 5. Evidence Integrity (Chain of Custody)

| Field | Value |
|---|---|
| Case/Lab Identifier | SBT-DF203-Lab6-AkinwaOmokunleAnthony |
| Evidence Files | `iptables_before.rules`, `iptables_before.txt`, `http_allowed.pcapng`, `http_blocked.pcapng`, `allowed_vs_blocked.tsv` |
| Source | Generated in authorized host-only lab network |
| Original SHA-256 (iptables before) | `b8c6e01285998f85ca87dadb5852a8c714da0afedd120a06c8dbc444753a44fb` |
| Working-Copy SHA-256 (iptables before) | `b8c6e01285998f85ca87dadb5852a8c714da0afedd120a06c8dbc444753a44fb` |
| http_allowed.pcapng SHA-256 | `bdb691732c8d3023068c04b16ae5ca2414931467ef5aa127d478de2561a2809d` |
| http_blocked.pcapng SHA-256 | `24352948613f9920932b8f812fd62326a1c9c42fb2af63c5ee31cddc440d9d7e` |
| Analysis Workstation | Kali Linux VM (`192.168.186.128`, `eth0`) |
| Client VM | Windows (`192.168.186.1`, VMnet8) |
| Gateway | `192.168.186.2` |
| Notes | Original ruleset preserved; only a single source-specific INPUT rule was added and removed. No other firewall changes made. |

> Full hash values and rule exports are stored in `reports/iptables_before_sha256.txt`, `reports/http_allowed_sha256.txt`, `reports/http_blocked_sha256.txt`, and `reports/iptables_before.rules`.

---

## 6. Methodology Summary

The analysis follows the sequence defined in the SBT-DF203 lecture slides:

1. **Part A — Record the Lab Network and Baseline Access:** Capture server interfaces, routes, Apache listener status, and verify baseline HTTP from the Windows client.
2. **Part B — Capture the Allowed HTTP Baseline:** Capture the TCP handshake + HTTP GET + HTTP 200 OK on the server while the client requests the page.
3. **Part C — Apply and Verify the Blocking Rule:** Insert a source-specific DROP rule at the top of INPUT and verify it is present with `iptables -C`.
4. **Part D — Capture Blocked Traffic and Rule Counters:** Re-run the client request, capture the client-side SYN attempts, and record the DROP rule's incrementing counter.
5. **Part E — Compare Allowed and Blocked Captures:** Extract SYN flags, HTTP requests/responses, and retransmission evidence from both captures into a single side-by-side comparison.
6. **Part F — Remove the Rule and Restore Access:** Delete the rule by specification (not line number), confirm removal, and verify HTTP access is restored from the client.

---

## 7. Reports and Artifacts

| File | Description |
|---|---|
| `reports/iptables_before.rules` | Original firewall ruleset export (`iptables-save`) |
| `reports/iptables_before.txt` | Original INPUT/FORWARD/OUTPUT chains (`iptables -L -n -v`) |
| `reports/iptables_before_sha256.txt` | SHA-256 of the original ruleset |
| `reports/server_interfaces.txt` | Server interface and route listing |
| `reports/apache_listener.txt` | Apache listening socket (`ss -lntp`) |
| `reports/http_allowed.pcapng` | Allowed HTTP capture |
| `reports/http_allowed_sha256.txt` | SHA-256 of the allowed capture |
| `reports/iptables_after_add.txt` | INPUT chain after adding the DROP rule |
| `reports/rule_verification.txt` | `iptables -C` verification output |
| `reports/http_blocked.pcapng` | Blocked HTTP capture |
| `reports/http_blocked_sha256.txt` | SHA-256 of the blocked capture |
| `reports/iptables_after_test.txt` | INPUT chain after the blocked test (counter incremented) |
| `reports/allowed_vs_blocked.tsv` | Side-by-side packet comparison |
| `reports/iptables_restored.txt` | INPUT chain after rule removal |
| `reports/rule_removed.txt` | Confirmation that the rule was removed |

Screenshots referenced in the report are stored in `screenshots/` as `Fig X.Y - <caption>.png` and referenced in the report narrative.

---

## 8. Key Findings (Summary)

| Question | Finding |
|---|---|
| Server IP / MAC / port | `192.168.186.128` / `00:0c:29:2c:6b:37` / TCP 80 |
| Client IP / MAC | `192.168.186.1` (VMnet8) |
| Gateway | `192.168.186.2` |
| Baseline access | `HTTP/1.1 200 OK` (Apache 2.4.68) |
| Blocking rule position | INPUT chain, line 1 (top of chain) |
| Rule target | `DROP` |
| Rule scope | `-s 192.168.186.1 -p tcp --dport 80` |
| Allowed capture evidence | Full handshake + `GET /firewall_lab.html` + `HTTP/1.1 200 OK` |
| Blocked capture evidence | Repeated SYN, no SYN-ACK, SYN retransmissions |
| DROP counter after test | 4 packets matched (from `iptables_after_test.txt`) |
| Client result (blocked) | `curl: (28) Failed to connect ... Timeout was reached` (10013 ms) |
| Restoration | Rule removed by specification; HTTP access restored |
| Key limitations | An empty SYN capture without SYN-ACK does not on its own prove a firewall block; server-down and network faults can produce similar evidence, so counters and application health must also be checked. |

---

## 9. Evidential Limitations

- `DROP` silently discards packets without notifying the client — this is why the client sees only a timeout, not a rejection. A capture alone cannot prove *where* the SYN was lost; corroborating evidence (firewall counters, `ss -lntp`, application health) is required.
- A `REJECT` rule would produce different evidence: an immediate ICMP Destination Unreachable or TCP RST, visible in the capture and reported by the client as `Connection refused` or `Connection reset by peer`.
- Port number alone does not indicate firewall behaviour; rule position and target action must be examined.
- If the server is down rather than firewall-blocked, the capture would still show a client SYN but with no matching iptables counter increment.
- Deleting a rule by line number is unsafe if other rules have changed since the last listing; always delete by specification.

---

## 10. Ethical Handling of Evidence

As required by the lab instructions:

- The original firewall ruleset was exported and SHA-256 hashed **before** any change to support rollback and integrity.
- Only a source-specific rule was applied; no firewall flush or broad blocking was performed.
- The rule was removed after evidence collection, and the INPUT chain was confirmed restored to its baseline.
- All packets and rule exports are treated as **confidential assessment evidence**; no sensitive data was published outside this repository.

---

## 11. Reproducibility

All commands used in this analysis are documented in the corresponding `reports/*.txt`, `reports/*.tsv`, and `reports/*.rules` files. Anyone with the same two-VM setup (Kali server + Windows client on an isolated host-only network) can reproduce the analysis by following the SBT-DF203 Lab 6 procedure and running the same `iptables` and `tshark` commands.

---

## 12. References

- ICDFA SBT-DF203 — Basic Networking Skills for Digital Forensics, Lab 6: Firewall Traffic Control and Forensic Verification.
- `iptables(8)` and `iptables-save(8)` man pages.
- RFC 793 — Transmission Control Protocol.
- RFC 792 — Internet Control Message Protocol.
- Wireshark Display Filter Reference — `tcp.flags`, `tcp.analysis.retransmission`, `http.*` fields.

---
