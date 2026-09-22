# SBT-DF203 — Lab 6: Firewall Traffic Control and Forensic Verification

**Course:** Basic Networking Skills for Digital Forensics  
**Course Code:** SBT-DF203  
**Lab Number:** Lab 6  
**Lab Title:** Firewall Traffic Control and Forensic Verification  
**Delivery Block:** 2/3 of 3  
**Scheduled Dates:** 12–18 September 2026  
**Prepared by:** Aminu Idris, AMCPN — Founder, ICDFA  
**Analyst:** Akinwa Omokunle Anthony  
**Reg No:** 2025/FWSD/11206  
**Analysis Workstation:** Kali Linux VM (`192.168.186.128`, `eth0`)

---

## Executive Summary

This practical validated a Linux host-based firewall's ability to control HTTP traffic from one authorized lab client while allowing another. The lab used an isolated host-only VMnet8 network comprising a Kali Linux VM acting as the protected server and a Windows client VM acting as the requesting host. Apache 2.4.68 (Debian) served a training page at `http://192.168.186.128/firewall_lab.html`. TShark captured baseline allowed HTTP traffic and then blocked traffic after a narrowly scoped `iptables` INPUT rule was inserted. The rule was applied only to the assigned blocked client IP, verified with `iptables -C`, and removed after evidence collection. Firewall counters, packet capture evidence and client-side `curl` output were correlated to demonstrate the difference between permitted and dropped HTTP sessions. The original firewall ruleset was exported and SHA-256 hashed before any change to support evidence integrity and safe rollback.

---

## 1. Lab Folder Structure

The evidence workspace was created following the ICDFA standard forensic folder layout: `evidence/` for original artifacts, `working/` for analysis copies, `reports/` for extracted outputs, `screenshots/` for figures, `scripts/` for tooling, and `exported/` for derived artifacts.

![Lab folder structure](screenshots/Fig%201.1%20Lab6%20folder%20structure.png)

*Fig 1.1 — Lab 6 folder structure*

---

## 2. Training Webpage Served by Apache

A minimal lab page was deployed to `/var/www/html/firewall_lab.html` on the Kali server. Apache was started and enabled at boot.

![Training webpage](screenshots/Fig%201.2%20%E2%80%94%20Training%20webpage%20served%20by%20Apache.png)

*Fig 1.2 — Training webpage served by Apache*

---

## 3. Evidence Integrity and Chain of Custody

Before any firewall change, the original ruleset was exported with `iptables-save` and hashed with SHA-256.

![iptables-save output](screenshots/Fig%201.3%20-%20The%20iptables-save%20output%20(the%20ruleset%20file).png)

*Fig 1.3 — The `iptables-save` output (the ruleset file)*

The live INPUT chain was also listed with `iptables -L -n -v --line-numbers` to capture the baseline state.

![Original iptables listing](screenshots/Fig%201.4%20-%20Original%20iptables%20listing.png.png)

*Fig 1.4 — Original iptables listing*

The hash of the original ruleset was recorded in `reports/iptables_before_sha256.txt`:
b8c6e01285998f85ca87dadb5852a8c714da0afedd120a06c8dbc444753a44fb reports/iptables_before.rules

text

![SHA-256 of original ruleset](screenshots/Fig%201.5%20-%20SHA-256%20of%20exported%20ruleset.png.png)

*Fig 1.5 — SHA-256 of the exported ruleset*

### Mini Chain of Custody

| Field | Value |
|---|---|
| Case/lab identifier | SBT-DF203-Lab6-AkinwaOmokunleAnthony |
| Trainee name | Akinwa Omokunle Anthony |
| Date and time started | 18th September, 2026, 19:52 WAT |
| Evidence files | `iptables_before.rules`, `iptables_before.txt`, `http_allowed.pcapng`, `http_blocked.pcapng`, `allowed_vs_blocked.tsv` |
| Source | Generated in authorized host-only lab network |
| Original SHA-256 (iptables before) | `b8c6e01285998f85ca87dadb5852a8c714da0afedd120a06c8dbc444753a44fb` |
| Working-copy SHA-256 | Same — original preserved |
| Analysis workstation | Kali Linux VM, interface `eth0`, MAC `00:0c:29:2c:6b:37` |
| Client VM | Windows, `192.168.186.1` (VMnet8) |
| Gateway | `192.168.186.2` |
| Notes | Only a single source-specific INPUT rule was applied and removed. No other firewall changes were made. |

---

## 4. Part A — Record the Lab Network and Baseline Access

Server interfaces, routes and Apache listener were recorded on the Kali server:

![Server interfaces and routes](screenshots/Fig%202.1%20-%20Server%20interfaces%20and%20routes%20and%20Apache%20listener.png)

*Fig 2.1 — Server interfaces, routes, and Apache listener*

Baseline HTTP access was verified from the Windows client with `curl -v`:
Trying 192.168.186.128:80...

Connected to 192.168.186.128 (192.168.186.128) port 80 (#0)

GET /firewall_lab.html HTTP/1.1
Host: 192.168.186.128
User-Agent: curl/8.0.1
Accept: */*

< HTTP/1.1 200 OK
< Server: Apache/2.4.68 (Debian)
< Content-Length: 117
< Content-Type: text/html
<

<!DOCTYPE html><html><body><h1>ICDFA Network Forensics Firewall Lab</h1><p>Server:MyApacheServer </p></body></html> ```
https://screenshots/Fig%202.2%20%E2%80%93%20Baseline%20curl%20-v%20success%20from%20client.png

Fig 2.2 — Baseline curl -v success from client

Field	Value
Server IP	192.168.186.128
Server interface	eth0
Server MAC	00:0c:29:2c:6b:37
Client IP	192.168.186.1
Gateway	192.168.186.2
Baseline result	HTTP/1.1 200 OK
5. Part B — Capture the Allowed HTTP Baseline
A capture was started on the server in the foreground, followed immediately by a curl request from the Windows client.

https://screenshots/Fig%202.3%20%E2%80%93%20Start%20the%20allowed%20capture%20(foreground).png

Fig 2.3 — Start of the allowed capture (foreground)

After the capture completed, the resulting PCAPNG was hashed:

text
bdb691732c8d3023068c04b16ae5ca2414931467ef5aa127d478de2561a2809d  evidence/http_allowed.pcapng
https://screenshots/Fig%202.4%20-%20Hash%20it.png

Fig 2.4 — Hash of the allowed capture

6. Part C — Apply and Verify the Blocking Rule
A single blocking rule was inserted at position 1 of the INPUT chain, scoped only to the assigned blocked client IP:

bash
BLOCKED_CLIENT_IP=192.168.186.1
iptables -I INPUT 1 -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP
The rule's presence was verified with iptables -C:

text
Rule verified present.
https://screenshots/Fig%203.1%20%E2%80%94%20iptables%20-L%20INPUT%20after%20adding%20DROP%20rule.png

Fig 3.1 — iptables -L INPUT after adding DROP rule

Field	Value
Rule position	INPUT chain, line 1
Source	192.168.186.1
Protocol / port	TCP / 80
Target	DROP
Verification	iptables -C returned "Rule verified present."
7. Part D — Capture Blocked Traffic and Rule Counters
A second capture was taken while the Windows client retried the request. The packet capture showed repeated client SYN packets with no SYN-ACK from the server.

https://screenshots/Fig%204.1%20%E2%80%94%20Wireshark%20blocked%20capture%20showing%20SYN%20retransmissions.png

Fig 4.1 — Wireshark blocked capture showing SYN retransmissions

The Windows client's curl timed out after 10 seconds:

text
*   Trying 192.168.186.128:80...
* ipv4 connect timeout after 10000ms, move on!
* Failed to connect to 192.168.186.128 port 80 after 10013 ms: Timeout was reached
* Closing connection 0
curl: (28) Failed to connect to 192.168.186.128 port 80 after 10013 ms: Timeout was reached
https://screenshots/Fig%204.2%20%E2%80%93%20Windows%20client%20Output%20after%20blocked.png

Fig 4.2 — Windows client output after blocked

The DROP rule's packet counter incremented as expected:

text
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        4   240 DROP       tcp  --  *      *       192.168.186.1        0.0.0.0/0            tcp dpt:80
Blocked capture summary:

Item	Value
Capture file	evidence/http_blocked.pcapng
SHA-256	24352948613f9920932b8f812fd62326a1c9c42fb2af63c5ee31cddc440d9d7e
Filter	host 192.168.186.1 and tcp port 80
DROP rule counter after test	4 packets / 240 bytes
Client result	curl: (28) Timeout was reached
8. Part E — Compare Allowed and Blocked Captures
Both captures were parsed with the same tshark filter to extract SYN flags, HTTP request/response fields, and retransmission indicators.

https://screenshots/Figure%205.1%20-%20Compare%20both%20captures.png

Fig 5.1 — Compare both captures

Comparison:

Indicator	Allowed Capture	Blocked Capture
Client SYN visible?	Yes	Yes
Server SYN-ACK visible?	Yes	No
Handshake completed?	Yes	No
HTTP GET visible?	Yes (GET /firewall_lab.html)	No
HTTP response visible?	Yes (HTTP/1.1 200 OK)	No
Retransmissions / timeouts	None	Repeated SYN retransmissions
iptables counter change	0 (rule not applied)	4 packets matched
curl result	HTTP/1.1 200 OK	curl: (28) Timeout was reached
The three independent lines of evidence — packet capture, firewall counter, and client output — corroborate each other and prove the block was caused by the firewall, not by a server outage or network fault.

9. Part F — Remove the Rule and Restore Access
The blocking rule was removed using the exact same criteria used to insert it (deletion by specification, not by line number):

bash
iptables -D INPUT -s 192.168.186.1 -p tcp --dport 80 -j DROP
The INPUT chain returned to its baseline state and HTTP access was restored from the Windows client.

10. Forensic Interpretation Questions
1. Why does DROP commonly cause SYN retransmissions and a timeout?

DROP silently discards the SYN without notifying the client. TCP has no way to know the port is unreachable, so it retransmits the SYN with exponential backoff until the connect timer expires. The capture shows repeated identical SYN packets and curl reports a connection timeout — no RST, no ICMP, just silence.

2. How would a REJECT rule differ in the packet capture and client output?

REJECT actively replies. With --reject-with icmp-port-unreachable (default for TCP), the client receives an ICMP Destination Unreachable immediately and curl fails fast with "Connection refused". With --reject-with tcp-reset, the client receives a TCP RST and curl reports "Connection reset by peer". In the capture, you'd see the SYN followed by ICMP or RST — not retransmissions.

3. Why are firewall counters valuable corroborating evidence?

Packet counters prove the rule was actually matched and the drop happened at the firewall, not somewhere else. Without counters, a blocked capture could be explained by a dead server, a broken route, or a client-side failure. A rising pkts count on the specific rule ties the observed packets directly to the firewall decision.

4. What evidence would show that the web server was down rather than firewall-blocked?

If the server is down, the SYN still reaches the host and the host replies with a TCP RST (no listener) or nothing at all (host offline). In a capture you'd see the SYN arrive, then either an RST from the server stack or no response with no matching iptables rule and no counter increment. Firewall-blocked traffic, by contrast, shows the SYN arriving at the interface, no RST or ICMP, no SYN-ACK, and the DROP rule's counter incrementing in lockstep with the retransmissions.

5. What is the risk of deleting a rule by line number after other rules have changed?

iptables -D INPUT <line> deletes whichever rule currently occupies that position. If any rule was inserted, deleted, or reordered since the last listing, the line number refers to a different rule — you can silently delete the wrong rule. Safer practice is to delete by specification (iptables -D INPUT -s <ip> -p tcp --dport 80 -j DROP) so the deletion targets the exact rule.

11. Key Findings
A source-specific DROP rule at the top of the INPUT chain blocked HTTP from one client without affecting other traffic.

DROP caused the client to time out because packets were silently discarded.

The block was visible in three independent places — packet capture, firewall counter, and client output.

Firewall counters are essential corroborating evidence — a non-zero counter proves the rule matched live traffic.

An empty SYN capture without a SYN-ACK does not on its own prove a firewall block; server-down and network faults can produce similar evidence, so counters and application health must also be checked.

The original ruleset was preserved and hashed before any change to allow safe rollback.

12. Evidential Limitations
DROP silently discards packets; a capture alone cannot prove where the SYN was lost — corroborating evidence (counters, ss -lntp, application health) is required.

REJECT produces different evidence: ICMP or TCP RST visible in the capture, and the client fails fast rather than timing out.

Port number alone does not indicate firewall behaviour; rule position and target action must be examined.

Deleting a rule by line number is unsafe if other rules have changed.

13. Ethical Handling of Evidence
The original firewall ruleset was exported and SHA-256 hashed before any change.

Only a source-specific rule was applied; no firewall flush or broad blocking was performed.

The rule was removed after evidence collection and the INPUT chain was confirmed restored.

No sensitive data was published outside this repository.

14. References
ICDFA SBT-DF203 — Basic Networking Skills for Digital Forensics, Lab 6: Firewall Traffic Control and Forensic Verification.

iptables(8), iptables-save(8), and iptables-restore(8) man pages.

RFC 793 — Transmission Control Protocol.

RFC 792 — Internet Control Message Protocol.

Wireshark Display Filter Reference — tcp.flags, tcp.analysis.retransmission, http.*.
