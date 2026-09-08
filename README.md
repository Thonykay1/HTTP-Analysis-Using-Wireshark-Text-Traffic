# HTTP-Analysis-Using-Wireshark-Text-Traffic
HTTP Network Forensics with Wireshark

A practical digital forensics project focused on capturing and analyzing a plaintext HTTP session in an isolated Linux laboratory environment.

Overview

In this lab, I created a local Apache web server and captured the network traffic generated when accessing the webpage. I then used Wireshark to analyze the packets and reconstruct the communication between the client and server.

The investigation focused on understanding how HTTP traffic is carried over TCP/IP and identifying useful network forensic evidence.

What I Did
Set up a local Apache HTTP server.
Created and accessed a local training webpage.
Captured HTTP traffic using Wireshark.
Analyzed the TCP three-way handshake.
Identified SYN, SYN-ACK and ACK packets.
Examined source and destination IP addresses and ports.
Analyzed TCP sequence and acknowledgement numbers.
Identified the HTTP GET request and server response.
Reconstructed the TCP conversation.
Examined HTTP headers and transmitted content.
Recorded packet timestamps to build a forensic timeline.
Calculated a SHA-256 hash to verify evidence integrity.
Tools Used
Kali Linux
Apache2
Wireshark
TShark
SHA-256
Key Learning

This project helped me understand how network traffic can be used as digital forensic evidence. I learned how different layers of network communication provide different types of information, from Ethernet and IP addresses to TCP connection details and HTTP application data.

I also learned the importance of preserving captured evidence and using cryptographic hashes to verify its integrity.

Evidence

The project contains the packet capture, analysis outputs, screenshots, hashes, and forensic report generated during the investigation.

Note: All traffic captured in this project was generated within an authorized, isolated laboratory environment for educational purposes.
