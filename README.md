# SBT-DF203 — HTTP Analysis Using Wireshark

## Basic Networking Skills for Digital Forensics — Lab 1

This project demonstrates a practical network forensic investigation of a controlled plaintext HTTP session using Wireshark/TShark.

A local Apache web server was used to generate HTTP traffic. The traffic was captured on the loopback interface and analysed at the TCP, IP, HTTP, and link layers.

The investigation focused on identifying the TCP three-way handshake, HTTP GET request, HTTP response, TCP connection termination, ports, sequence and acknowledgement numbers, timestamps, HTTP headers, and evidence integrity using SHA-256 hashing.

---

## 🎯 Objectives

- Explain HTTP, TCP, IP, and link-layer forensic artefacts.
- Create and capture a controlled plaintext HTTP session.
- Identify TCP SYN, SYN-ACK, and ACK packets.
- Identify source and destination IP addresses and ports.
- Examine TCP sequence and acknowledgement numbers.
- Extract HTTP requests, responses, and headers.
- Reconstruct a TCP conversation.
- Analyse timestamps and TCP connection termination.
- Calculate SHA-256 hashes for captured evidence.
- Prepare a concise forensic timeline and findings report.

---

## 🛠️ Tools Used

- Kali Linux
- Apache2
- Wireshark
- TShark
- cURL
- SHA-256
- Linux command line

---

## 📁 Project Structure

```text
SBT-DF203-Lab1/
├── evidence/
│   └── basic.pcapng
│
├── working/
│   └── basic_working.pcapng
│
├── reports/
│   ├── curl_verbose.txt
│   ├── capture_hashes.txt
│   └── connection_close.tsv
│
├── screenshots/
│   └── [Wireshark screenshots]
│
├── scripts/
│   └── [optional scripts]
│
└── README.md
