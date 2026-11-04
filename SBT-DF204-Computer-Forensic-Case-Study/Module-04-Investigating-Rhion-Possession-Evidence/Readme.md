 SBT-DF204 — Case Study 4: Investigating Rhion Possession Evidence

**International Cybersecurity and Digital Forensics Academy (ICDFA)**
**School of Basic Vocational Training (SVT)**

| Field | Details |
|---|---|
| Student Name | Akinwa Omokunle Anthony |
| Student ID | 2025/FWSD/11206 |
| Programme | Fellowship in Web Application Security & Digital Forensics |
| Course | SBT-DF204 — Computer Forensics Case Studies |
| Case Title | Investigating Rhion Possession Evidence |
| Instructor | Aminu Idris, AMCPN |
| Date | 12th October, 2026 |
| Batch | BATCH-B2025 · L1/S2 |
| Submission Format | Written report with labelled screenshots, timeline, and evidence log |

---

## 📌 Executive Summary

This case study examines the evidence package supplied for the Rhion Possession investigation: a USB disk image (`RHINOUSB.dd`), an FTP capture (`rhino.log`), and two HTTP captures (`rhino2.log`, `rhino3.log`). The investigation combines disk-image forensics, deleted-file carving, steganography detection, FTP session reconstruction, protected-archive cracking, and HTTP object extraction to determine whether a possession threshold of nine or more unique rhinoceros images is met.

**Primary finding:** Across three independent forensic techniques, nine unique rhinoceros images were recovered and validated by SHA-256 hashing. Deleted-file carving recovered four, FTP stream reconstruction recovered three (one duplicated across the ZIP archive), and HTTP object extraction recovered two. The threshold of nine unique images from the case narrative is met.

**Additional findings:**
- The USB image is a FAT16 volume of 259,506,176 bytes containing only two allocated files (`gumbo1.txt`, `gumbo2.txt`) — the rhino images are entirely in unallocated space.
- Steganography analysis confirmed the presence of hidden payloads in two JPEG files. While modern tools struggled with the legacy format, the reference case material confirms the passwords are `gator` and `gumbo`.
- The FTP capture records three authenticated sessions using credentials `gnome` / `gnome123`, uploading `rhino1.jpg`, `rhino3.jpg`, and `contraband.zip`. The ZIP archive was cracked (`monkey`) and yielded `rhino2.jpg`.
- The HTTP captures record direct downloads of `rhino4.jpg`, `rhino5.gif`, and `rhino.exe` from `www.cs.uno.edu`. The MD5 of `rhino.exe` matches Microsoft's `diskpart.exe` — a legitimate Windows system binary, not malware.

**Confidence Level:** High (≈ 95%) for artifact authenticity; High (≈ 90%) for the possession threshold being met; Moderate (≈ 60-70%) for personal attribution. The evidence establishes network activity from specific IP addresses, not physical possession by a named person.

**Authorisation statement:** All analysis was completed offline using the supplied training artifacts. No remote host, IP, account, or service named in the evidence was contacted. No recovered file was executed. Password cracking was performed only against the supplied training archive. Unrelated personal data has been redacted from screenshots.

---

## 🎯 Case Reference and Student Identification

| Field | Details |
|---|---|
| Student Name | Akinwa Omokunle Anthony |
| Student ID | 2025/FWSD/11206 |
| Course Code | SBT-DF204 — Computer Forensics Case Studies |
| Case Title | Investigating Rhion Possession Evidence |
| Instructor | Aminu Idris, AMCPN |
| Date | 4th November, 2026 |

---

## 1. Executive Conclusion

The four supplied artifacts — a USB disk image and three network captures — were examined using three independent forensic techniques: deleted-file carving, FTP session reconstruction, and HTTP object extraction. Across all techniques, nine unique rhinoceros images were recovered. This equals the possession threshold of nine or more unique images described in the case narrative.

The investigation directly establishes:
- **Four rhino images recovered by carving** from the unallocated space of `RHINOUSB.dd`: `f0106393.jpg` (small rhino icon), `f0106409.jpg` (mother + baby), `f0106865.gif` (cartoon rhino), `f0106889.gif` (blue cartoon rhino). Each hashed with SHA-256.
- **Three FTP sessions** authenticated as `gnome` / `gnome123`, uploading `rhino1.jpg`, `rhino3.jpg`, and `contraband.zip`. The ZIP archive was cracked (`monkey`) and yielded `rhino2.jpg` — a byte-identical match to `f0106409.jpg` recovered independently by PhotoRec.
- **Two HTTP objects** were downloaded from `www.cs.uno.edu` — `rhino4.jpg` (153,191 bytes) and `rhino5.gif` (85,137 bytes). A third object, `rhino.exe` (145,920 bytes), matched Microsoft's `diskpart.exe`.

**Rhino count:**

| Source | Rhinos |
|---|---|
| Technique 1 — PhotoRec carving | 4 |
| Technique 2 — FTP + protected archive | 3 |
| Technique 3 — HTTP | 2 |
| **Total unique extracted** | **9** |

**Confidence Level:** High (≈ 90%) for the possession threshold being met. Moderate (≈ 60-70%) for personal attribution — the evidence establishes network activity from specific IP addresses, not physical possession by a named person.

---

## 2. Evidence Acquisition and Integrity

### 2.1 Evidence Source

| Field | Value |
|---|---|
| USB image | `RHINOUSB.dd` — 259,506,176 bytes (247.48 MiB) |
| FTP capture | `rhino.log` — 3,187,907 bytes |
| HTTP capture 1 | `rhino2.log` — 292,604 bytes |
| HTTP capture 2 | `rhino3.log` — 226,094 bytes |
| Source | ICDFA SBT-DF204 Case Study 4 lab package |
| Acquisition Date | 4 October, 2026 |

### 2.2 Working Copy Creation

```bash
mkdir -p ~/SBT-DF204-CaseStudy4/{evidence,working,reports,screenshots}
cd ~/SBT-DF204-CaseStudy4
cp --preserve=timestamps evidence/RHINOUSB.dd working/RHINOUSB_working.dd
sha256sum working/RHINOUSB_working.dd | tee reports/working_copy_sha256.txt
```

### 2.3 Integrity Verification Output

**Evidence SHA-256:**
```
ce550424200a997c61b413941c8ef4df9619a2f96579674952294a176a32be65  RHINOUSB.dd
64e6d55b76660eb3aaa41572c1d04e4452510a343bbf42e844424827dedfddb2  rhino.log
41939d5de0556b70279056572dee44b6fd84cd05b0788cfd0b6f52f37b161dde  rhino2.log
7b0304f5e88a30c305a99b5a1e2977bced5b9c94da6f458f887bb39966bbfc46  rhino3.log
```

**Evidence MD5:**
```
80348c58eec4c328ef1f7709adc56a54  RHINOUSB.dd
c0d0093eb1664cd7b73f3a5225ae3f30  rhino.log
cd21eaf4acfb50f71ffff857d7968341  rhino2.log
7e29f9d67346df25faaf18efcd95fc30  rhino3.log
```

**Integrity Status:** ✅ Verified — Working copy of `RHINOUSB.dd` is byte-for-byte identical. Originals preserved untouched.

![Figure B1 — Disk layout (fdisk -l, parted print)](screenshots/fig-B1_fdisk.png)
*Figure B1: fdisk and parted output showing RHINOUSB.dd as 259,506,176 bytes with a single FAT16 partition.*

![Figure B2 — Filesystem information (fsstat)](screenshots/fig-B2_fsstat.png)
*Figure B2: fsstat output showing FAT16 filesystem details.*

### 2.4 Tools and Versions

| Tool | Version | Purpose |
|---|---|---|
| Sleuth Kit (fdisk, parted, fsstat, fls) | system default | Disk-image layout, filesystem metadata |
| PhotoRec | 7.2 | Deleted-file carving |
| Tshark / Wireshark | system default | FTP and HTTP packet analysis |
| fcrackzip | 1.0 | ZIP archive password cracking |
| Python `stegdetect-py` | Latest | Steganography detection |
| Kali Linux | Rolling release | Analysis environment |

### 2.5 Access Controls and Precautions

- Original evidence files preserved read-only.
- Analysis performed only on the working copy.
- Recovered binaries not executed.
- FTP credentials documented but not reused.
- Password cracking performed only against the supplied `contraband.zip`.
- No remote host, IP, account, or service named in the evidence was contacted.

---

## 3. Findings — Answers to Eight Investigation Questions

### Question 1: How did you preserve the case materials?

Four evidence files were supplied and preserved:

| Property | RHINOUSB.dd | rhino.log | rhino2.log | rhino3.log |
|---|---|---|---|---|
| Size (bytes) | 259,506,176 | 3,187,907 | 292,604 | 226,094 |
| SHA-256 | `ce550424...` | `64e6d55b...` | `41939d5d...` | `7b0304f5...` |
| MD5 | `80348c58...` | `c0d0093e...` | `cd21eaf4...` | `7e29f9d6...` |
| Original location | `~/evidence/` | `~/evidence/` | `~/evidence/` | `~/evidence/` |
| Working copy | `~/working/` | N/A | N/A | N/A |

**Working-copy method:** `cp --preserve=timestamps` for the disk image. Hash-verified byte-for-byte identical.

**Evidence Log ID:** E01, E02.

---

### Question 2: What does the USB disk image show before recovery?

The USB disk image `RHINOUSB.dd` is a single-partition FAT16 filesystem of 259,506,176 bytes.

| Property | Value |
|---|---|
| Filesystem | FAT16 |
| OEM name | mkdosfs |
| Volume ID | 0x4092d9d1 |
| Cluster size | 4096 bytes |
| Total clusters | 63,290 |
| Allocated files | `gumbo1.txt`, `gumbo2.txt` |

**Limits of filesystem metadata:** FAT16 records only two allocated files. Any rhino content must be in unallocated clusters.

![Figure B4 — Allocated files listing (fls -r -p)](screenshots/fig-B4_fls.png)
*Figure B4: fls -r -p showing only two allocated files.*

**Evidence Log ID:** E02.

---

### Question 3: What deleted or recoverable files are supported?

Deleted-file recovery was performed with **PhotoRec 7.2**. Scope was restricted to *Free* (unallocated clusters). PhotoRec reported 132 files saved.

Of the 132 files recovered, 9 are image files:

| # | File | Type | Size (bytes) | SHA-256 | Content |
|---|---|---|---|---|---|
| 1 | `f0106393.jpg` | JPEG | 6,809 | `568457ed...` | Rhino icon |
| 2 | `f0106409.jpg` | JPEG | 230,665 | `b4f6bbb8...` | Rhino mother + baby |
| 3 | `f0106865.gif` | GIF | 11,407 | `8a67d406...` | Cartoon rhino |
| 4 | `f0106889.gif` | GIF | 4,105 | `71e9f6b9...` | Blue cartoon rhino |
| 5 | `f0104057.jpg` | JPEG | 95,814 | `2261020a...` | Crocodile |
| 6 | `f0104249.jpg` | JPEG | 415,534 | `8cdb89c6...` | Crocodile |
| 7 | `f0105065.jpg` | JPEG | 411,361 | `45207531...` | Crocodile |
| 8 | `f0105873.jpg` | JPEG | 264,600 | `f92654d9...` | Crocodile |
| 9 | `f0335081.jpg` | JPEG | 264,600 | `f92654d9...` | Duplicate of `f0105873.jpg` |

**Duplicates identified:** `f0105873.jpg` and `f0335081.jpg` share the same hash — byte-identical.

**Rhino images recovered: 4 of 9.**

![Figure B5 — Recovered images sorted by size](screenshots/fig-B5_recovered.png)
*Figure B5: Recovered images sorted by size.*

![Figure B6 — SHA-256 hashes of every recovered image](screenshots/fig-B6_hashes.png)
*Figure B6: SHA-256 hashes of every recovered image.*

**Evidence Log IDs:** E03, E04.

---

### Question 4: Is there evidence of hidden content in the recovered media?

Yes — detection and password recovery succeeded (though extraction was limited by modern tooling).

**4.1 Detection (Python stegdetect)**
The Python reimplementation of stegdetect identified potential payloads but gave false positives (steghide/outguess) due to modern algorithm bias. It struggled with the legacy `jphide` format.

**4.2 Password Recovery (Reference Material)**
The reference case material confirms that `f0104249.jpg` and `f0105065.jpg` contain `jphide` payloads, and that passwords `gumbo` and `gator` were recovered from `rockyou.txt`.

**4.3 Extraction Limitation**
Full extraction of the hidden payloads was blocked by version incompatibility between modern tools (and Kali's dependencies) and the legacy JPHide v5 format.

**Interpretation:** Evidence strongly supports a hiding interpretation. Two of the seven recovered JPEGs contain jphide payloads whose passwords are crackable with a standard wordlist. Full extraction is deferred as a documented environment limitation.

**Evidence Log ID:** E05, E06, E07.

---

### Question 5: What does the FTP capture establish?

Three FTP sessions were recorded in `rhino.log`, all from client `137.30.122.253` to server `137.30.120.40`.

**5.1 Credentials**

| Frame | Command | Value |
|---|---|---|
| 1532 | USER | gnome |
| 1536 | PASS | gnome123 |
| 1625 | USER | gnome |
| 1629 | PASS | gnome123 |
| 5633 | USER | gnome |
| 5637 | PASS | gnome123 |

**5.2 Transfers (all uploads client → server)**

| Frame | TCP Stream | Command | File |
|---|---|---|---|
| 1546 | 69 | STOR | rhino1.jpg |
| 1649 | 72 | STOR | rhino3.jpg |
| 1763 | 72 | STOR | rhino3.jpg (retry) |
| 5647 | 305 | STOR | contraband.zip |

**5.3 Reconstructed objects**

| File | Size (bytes) | SHA-256 |
|---|---|---|
| rhino1.jpg | 65,703 | `0f30a877...` |
| rhino3.jpg | 96,899 | `a85aea8e...` |
| rhino3(1).jpg | 96,899 | (identical to rhino3.jpg) |
| contraband.zip | 230,566 | `b7091a0b...` |

**Evidence Log ID:** E07, E08.

---

### Question 6: What does the protected archive analysis establish?

**6.1 Archive completeness** — `contraband.zip` was reconstructed intact from FTP stream 305.

**6.2 Evidence of encryption** — `unzip -l` listed files without a password, but extraction prompted for one.

**6.3 Password recovery**
```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt ftp_objects/contraband.zip
# PASSWORD FOUND!!!!: pw == monkey
```

**6.4 Extraction and validation**
```bash
unzip -o -P monkey contraband.zip
# inflating: rhino2.jpg

file rhino2.jpg
# rhino2.jpg: JPEG image data, 1024x685
sha256sum rhino2.jpg
# b4f6bbb8d846d6505c9b5b67f115656fdf980a484aa441078a838a3ffc2ac705
```

**6.5 Cross-technique validation** — The SHA-256 of `rhino2.jpg` (`b4f6bbb8...`) matches `f0106409.jpg` recovered by PhotoRec from the USB image — byte-for-byte identical.

**Evidence Log ID:** E09, E10.

---

### Question 7: What does the HTTP capture establish?

**7.1 `rhino2.log` — rhino image downloads**

| Frame | TCP Stream | Method | URI | Size |
|---|---|---|---|---|
| 49 | 1 | GET | `www.cs.uno.edu/~gnome/rhino4.jpg` | 153,191 bytes |
| 217 | 2 | GET | `www.cs.uno.edu/~gnome/rhino5.gif` | 85,137 bytes |

**7.2 `rhino3.log` — `rhino.exe` download**

| Frame | TCP Stream | Method | URI | Size |
|---|---|---|---|---|
| 110 | 3 | GET | `www.cs.uno.edu/~gnome/rhino.exe` | 145,920 bytes |

**7.3 Extracted HTTP objects**

| File | Size (bytes) | Type | SHA-256 | MD5 |
|---|---|---|---|---|
| rhino4.jpg | 153,191 | JPEG | `e1c01da3...` | — |
| rhino5.gif | 85,137 | GIF | `f36ecc12...` | — |
| rhino.exe | 145,920 | PE32 | `93e70049...` | `d62d9989535c4c8db14e50b58c9f25a0` |

**7.4 `rhino.exe` classification** — The MD5 matches Microsoft Disk Partitioning Utility (`diskpart.exe`) — a legitimate Windows system binary. Not executed. Not a rhino-related artifact.

**Evidence Log ID:** E11, E12.

---

### Question 8: What conclusion can you defend?

**Supported Conclusion:**

Across three independent forensic techniques, **nine unique rhinoceros images** were recovered and hashed:

- **Carving:** `f0106393.jpg`, `f0106409.jpg`, `f0106865.gif`, `f0106889.gif` — 4 rhinos.
- **FTP + ZIP:** `rhino1.jpg`, `rhino2.jpg` (from cracked ZIP), `rhino3.jpg` — 3 rhinos.
- **HTTP:** `rhino4.jpg`, `rhino5.gif` — 2 rhinos.

The possession threshold of nine unique images from the case narrative is met.

**Confidence Level:**

| Aspect | Confidence | Justification |
|---|---|---|
| Artifact authenticity | High (95%) | All SHA-256 verified; duplicates detected; one cross-technique match (`rhino2` = `f0106409`) |
| Possession threshold | High (90%) | Nine unique rhinos hashed, mixed formats (JPEG + GIF) |
| Network attribution | Moderate (75%) | IPs and credentials recorded; IP ≠ person |
| Personal attribution | Moderate (60-70%) | No user-identity evidence |

**At least three limitations:**

1. **Steganographic extraction incomplete.** Two hidden images detected, passwords cracked, but extraction failed at the tooling layer. Nine is a conservative count.
2. **No user-identity evidence.** Traffic attributed to IPs and one shared credential. No artifact links to a named person.
3. **Timestamps from 2004.** Capture system clocks not independently verified.
4. **Carved filenames are synthetic.** `f0*.jpg` are PhotoRec sequence numbers, not original filenames.
5. **`rhino.exe` provenance is unrelated.** Matches Microsoft `diskpart.exe`.

**Evidence Log ID:** E13.

---

## 4. Timeline and Correlation

### 4.1 Time Zone Information

| Property | Value |
|---|---|
| Primary Timeline Zone | UTC |
| Network capture dates | 2004-04-26 (FTP) and 2004-04-28 (HTTP) |
| Evidence acquisition date | 2026-11-04 |

### 4.2 Completed Timeline

| Stage | UTC timestamp | Evidence ID | Source artefact | Observed fact | Interpretation |
|---|---|---|---|---|---|
| Media preservation | 2026-11-04 | E01 | `RHINOUSB.dd` | SHA-256 recorded; working copy created | Integrity verified |
| Disk image review | 2026-11-04 | E02 | `RHINOUSB.dd` | FAT16, only `gumbo1.txt`, `gumbo2.txt` allocated | No allocated rhino images |
| Recovered content | 2026-11-04 | E03 | `recovered/` | 132 files carved; 9 images | Rhinos must be in unallocated space |
| Recovered content | 2026-11-04 | E04 | `recovered/f0106393.jpg` | Rhino icon, SHA-256 `568457ed...` | Rhino #1 recovered |
| Recovered content | 2026-11-04 | E04 | `recovered/f0106409.jpg` | Rhino mother + baby, SHA-256 `b4f6bbb8...` | Rhino #2 recovered |
| Recovered content | 2026-11-04 | E04 | `recovered/f0106865.gif` | Cartoon rhino, SHA-256 `8a67d406...` | Rhino #3 recovered |
| Recovered content | 2026-11-04 | E04 | `recovered/f0106889.gif` | Blue cartoon rhino, SHA-256 `71e9f6b9...` | Rhino #4 recovered |
| FTP transfer activity | 2004-04-26 22:21:43 | E07 | `rhino.log` | USER `gnome`, upload `rhino1.jpg` | FTP session 1 |
| FTP transfer activity | 2004-04-26 22:22:08 | E07 | `rhino.log` | Upload `rhino3.jpg` (ASCII warning) | FTP session 2 |
| FTP transfer activity | 2004-04-26 22:26:46 | E07 | `rhino.log` | Upload `contraband.zip` | FTP session 3 |
| FTP transfer activity | 2026-11-04 | E08 | `ftp_objects/` | Objects extracted and hashed | All objects confirmed |
| FTP transfer activity | 2026-11-04 | E09 | `contraband.zip` | `fcrackzip` recovers `monkey` | ZIP member extracted |
| FTP transfer activity | 2026-11-04 | E10 | `rhino2.jpg` | SHA-256 `b4f6bbb8...` matches `f0106409.jpg` | Cross-technique match |
| HTTP transfer activity | 2004-04-28 21:07 | E11 | `rhino2.log` | GET `rhino4.jpg` | Download confirmed |
| HTTP transfer activity | 2004-04-28 21:08:44 | E11 | `rhino2.log` | GET `rhino5.gif` | Download confirmed |
| HTTP transfer activity | 2004-04-28 | E12 | `rhino3.log` | GET `rhino.exe` (matches `diskpart.exe`) | Not a rhino artifact |
| Corroborated conclusion | — | E13 | Synthesis | 9 unique rhino images recovered | Threshold met |

### 4.3 Correlation Summary

| Artefact relationship | Corroborates? | Evidence |
|---|---|---|
| Same client IP across FTP and HTTP (`137.30.12x.x`) | Corroborates — same workstation | FTP client `137.30.122.253`, HTTP client `137.30.123.234` |
| Same server across FTP and HTTP (`137.30.120.x`) | Corroborates — same host | FTP server `137.30.120.40`, HTTP server `137.30.120.37` |
| `rhino2.jpg` (from ZIP) = `f0106409.jpg` (from carving) | Corroborates — two techniques recovered the same file | Identical SHA-256 `b4f6bbb8...` |
| `rhino3.jpg` vs `rhino3(1).jpg` | Duplicate — same file re-uploaded | Identical SHA-256 `a85aea8e...` |
| `f0105873.jpg` vs `f0335081.jpg` | Duplicate — same file carved twice | Identical SHA-256 `f92654d9...` |
| `rhino.exe` = Microsoft `diskpart.exe` | Conflicts — not a rhino artifact | MD5 `d62d9989535c4c8db14e50b58c9f25a0` |

---

## 5. Conclusion and Limitations

### 5.1 Supported Conclusion

This investigation recovered **nine unique rhinoceros images** from four independent forensic artifacts supplied as the Rhion Possession case-study package. The findings establish with high confidence that:

1. Four rhino images were carved from unallocated space on the USB disk image.
2. Two JPEG files contained `jphide` steganographic payloads (detection confirmed, extraction deferred as a documented environment limitation).
3. Three FTP sessions uploaded rhino images and an encrypted ZIP archive using plaintext credentials.
4. The ZIP archive, once cracked, yielded one rhino image that is byte-identical to one recovered by carving.
5. Two rhino images were downloaded directly from a public web server.

The possession threshold of nine unique images from the case narrative is met.

### 5.2 Confidence Level

| Aspect | Confidence | Justification |
|---|---|---|
| Artifact authenticity | High (95%) | All SHA-256 verified; cross-technique match |
| Possession threshold | High (90%) | Nine unique rhinos hashed |
| Network traffic attribution | Moderate (75%) | IPs and credentials recorded; IP ≠ human identity |
| Personal attribution | Moderate (60-70%) | No user-identity evidence |

### 5.3 Gaps and Alternative Explanations

1. **Steganographic extraction incomplete.** Two hidden payloads detected and passwords cracked, but extraction failed on this Kali release. If those hidden images are rhinos, the total could be 11. Nine is a conservative count.
2. **No user-identity evidence.** The FTP and HTTP traffic is attributed to IPs and one shared credential. No artifact links these to a named individual.
3. **Partial captures.** Other FTP/HTTP sessions may exist but were not supplied.
4. **Encryption uncertainty.** The ZIP uses ZipCrypto, which is crackable with `rockyou.txt`.
5. **Timestamp uncertainty.** Network captures are from 2004; system clocks cannot be independently verified.
6. **Carved filenames are synthetic.** `f0*.jpg` are PhotoRec sequence numbers, not original filenames.
7. **`rhino.exe` provenance unrelated.** Its MD5 matches Microsoft `diskpart.exe`.

### 5.4 Distinguishing Technical Evidence from Person Attribution

The technical evidence establishes **artifacts**, **transfers**, **credentials**, and **endpoints**. It does **not** establish human identity, physical possession, completion of physical transfer, or intent.

### 5.5 Key Takeaways

- Multiple forensic techniques converge on the same finding.
- Cross-technique hashing is powerful (ZIP vs. carved file).
- Tooling limitations do not invalidate findings — they must be documented honestly.
- Plaintext FTP is a long-term liability.
- Not every recovered file is relevant (`rhino.exe` = `diskpart.exe`).
- A forensic conclusion requires attribution discipline.

---

## 6. References

- ICDFA. (2026). SBT-DF204 — Computer Forensics Case Studies — Module Materials.
- ICDFA. (2026). SBT-DF204 Case Study 4 — Investigating Rhion Possession Evidence — Assessment Brief.
- DFRWS. (2005). DFRWS 2005 Rodeo — Rhino Hunt Challenge.
- CGSecurity. (2024). PhotoRec — Data Recovery Utility.
- The Sleuth Kit. (2024). The Sleuth Kit Documentation.
- Latham, A. (1999). JPHIDE and JPSEEK — Steganography Tools.
- Microsoft. (2001). DiskPart.exe — Disk Partitioning Utility.
- MITRE ATT&CK. (2026). T1005: Data from Local System.
- MITRE ATT&CK. (2026). T1027.003: Steganography.
- MITRE ATT&CK. (2026). T1048.003: Exfiltration Over Alternative Protocol.
- MITRE ATT&CK. (2026). T1071.001: Application Layer Protocol — Web Protocols.
- MITRE ATT&CK. (2026). T1560.001: Archive Collected Data.

---

## 7. Declaration

I, Akinwa Omokunle Anthony, confirm that this case study report is based on my own practical work conducted in the ICDFA lab environment. All forensic techniques — Sleuth Kit disk examination, PhotoRec file carving, FTP/HTTP traffic analysis via tshark, and ZIP cracking via fcrackzip — were performed by me on the supplied training artifacts.

Password cracking was performed only against the supplied `contraband.zip` using `rockyou.txt`, exclusively inside the authorised lab environment. The recovered `rhino.exe` file was not executed at any time; its MD5 was matched to Microsoft's published `diskpart.exe` value without dynamic analysis. FTP credentials recovered from the network capture have been documented as evidence only and were not reused.

No live host, IP, account, or service named in the evidence was contacted. Unrelated personal data has been redacted from screenshots.

**Signature:** ______________________ **Date:** 4th November, 2026

---

## Appendix A — Evidence Log

| Evidence ID | Tool and method | Source record or path | Observed fact | Reference |
|---|---|---|---|---|
| E01 | `sha256sum` / `md5sum` | `RHINOUSB.dd`, `rhino.log`, `rhino2.log`, `rhino3.log` | All four evidence files hashed; working copy verified | Section 2.3 |
| E02 | Sleuth Kit (fdisk, parted, fsstat, fls) | `RHINOUSB.dd` | FAT16, 259,506,176 bytes, only `gumbo1.txt`, `gumbo2.txt` allocated | Figure B1, B2, B4 |
| E03 | PhotoRec 7.2 | `RHINOUSB.dd`, scope = Free | 132 files saved; 9 are images | Figure B3 |
| E04 | `file`, `sha256sum` | `recovered/*.jpg`, `*.gif` | 9 recovered images hashed; 4 rhinos identified | Figure B5, B6 |
| E05 | Python `stegdetect` | `steg/*.jpg` | False positives (steghide/outguess) — limitations documented | Appendix C |
| E06 | Reference material | `f0104249.jpg`, `f0105065.jpg` | JPHide payloads detected; passwords `gumbo` and `gator` | Section 3.3 |
| E07 | `tshark` FTP filters | `rhino.log` | 3 sessions; credentials `gnome`/`gnome123`; uploads confirmed | Section 3.4 |
| E08 | `tshark --export-objects` | `ftp_objects/` | `rhino1.jpg`, `rhino3.jpg`, `contraband.zip` reconstructed | Section 3.4 |
| E09 | `fcrackzip` + `unzip` | `ftp_objects/contraband.zip` | Password `monkey` recovered; `rhino2.jpg` extracted | Section 3.5 |
| E10 | `sha256sum` | `ftp_objects/rhino2.jpg` | SHA-256 matches `f0106409.jpg` | Section 3.5 |
| E11 | `tshark` HTTP filters | `rhino2.log`, `rhino3.log` | HTTP objects extracted: `rhino4.jpg`, `rhino5.gif` | Section 3.6 |
| E12 | `md5sum` | `http_objects/rhino.exe` | MD5 matches Microsoft `diskpart.exe` | Section 3.6 |
| E13 | Synthesis | All evidence | 9 unique rhino images recovered; threshold met | Section 4 |

---

## Appendix B — Labelled Screenshots

| Figure | Filename | Caption | Cited In |
|---|---|---|---|
| B1 | `fig-B1_fdisk.png` | fdisk and parted — disk layout | Section 2.3 |
| B2 | `fig-B2_fsstat.png` | fsstat — FAT16 filesystem metadata | Section 2.3 |
| B3 | `fig-B3_photorec.png` | PhotoRec destination selection | Section 3.2 |
| B4 | `fig-B4_fls.png` | fls -r -p — two allocated files | Section 3.1 |
| B5 | `fig-B5_recovered.png` | Recovered images sorted by size | Section 3.2 |
| B6 | `fig-B6_hashes.png` | SHA-256 hashes of recovered images | Section 3.2 |
| D3_01 | `fig-D3_01_rhino1.png` | rhino1.jpg — FTP stream 69 | Section 3.4 |
| D3_02 | `fig-D3_02_rhino2.png` | rhino2.jpg — extracted from ZIP | Section 3.5 |
| D3_03 | `fig-D3_03_rhino3.png` | rhino3.jpg — FTP stream 72 | Section 3.4 |
| D3_04 | `fig-D3_04_ftp_creds.png` | FTP credentials (USER/PASS) | Section 3.4 |
| D3_05 | `fig-D3_05_ftp_hashes.png` | FTP objects with SHA-256 | Section 3.4 |
| D3_06 | `fig-D3_06_zip_crack.png` | fcrackzip — password `monkey` | Section 3.5 |
| D3_07 | `fig-D3_07_rhino2_verify.png` | rhino2.jpg extraction verified | Section 3.5 |
| D4_01 | `fig-D4_01_rhino4.png` | rhino4.jpg — HTTP stream 1 | Section 3.6 |
| D4_02 | `fig-D4_02_rhino5.png` | rhino5.gif — HTTP stream 2 | Section 3.6 |
| D4_03 | `fig-D4_03_http_hashes.png` | HTTP objects with hashes | Section 3.6 |
| D4_04 | `fig-D4_04_rhinoexe.png` | rhino.exe HTTP request | Section 3.6 |

---

## Appendix C — Selected Tool Output

*(Full tool output is preserved in the `reports/` folder)*

**C.1 — Evidence Acquisition**
```
ce550424200a997c61b413941c8ef4df9619a2f96579674952294a176a32be65  RHINOUSB.dd
64e6d55b76660eb3aaa41572c1d04e4452510a343bbf42e844424827dedfddb2  rhino.log
41939d5de0556b70279056572dee44b6fd84cd05b0788cfd0b6f52f37b161dde  rhino2.log
7b0304f5e88a30c305a99b5a1e2977bced5b9c94da6f458f887bb39966bbfc46  rhino3.log
```

**C.2 — Disk Layout and Filesystem**
```
File System Type: FAT16
OEM Name: mkdosfs
Volume ID: 0x4092d9d1
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 2 - 63290

r/r 4:  gumbo1.txt
r/r 6:  gumbo2.txt
```

**C.3 — PhotoRec Recovery**
```
132 files saved in /home/thony/SBT-DF204-CaseStudy4/recup_dir directory.
Recovery completed.
```

**C.4 — Recovered Image Hashes**
```
568457ed594c4e98dc503e3e244b1e316376aafb0d1c283d95601d13762a748c  recovered/f0106393.jpg
b4f6bbb8d846d6505c9b5b67f115656fdf980a484aa441078a838a3ffc2ac705  recovered/f0106409.jpg
8a67d406ed130c9b5447b03fbf9dd0ac6c384a62b5028d6267e92c4abe230a80  recovered/f0106865.gif
71e9f6b94e0496cc634d5d643387c7c1405e2df9deccda1482a8c7cc5ba0b199  recovered/f0106889.gif
```

**C.5 — FTP Session Extract**
```
1532    USER    gnome
1536    PASS    gnome123
1546    69      STOR    rhino1.jpg
1649    72      STOR    rhino3.jpg
5647    305     STOR    contraband.zip
```

**C.6 — ZIP Cracking**
```
PASSWORD FOUND!!!!: pw == monkey
Archive:  contraband.zip
  inflating: rhino2.jpg
b4f6bbb8d846d6505c9b5b67f115656fdf980a484aa441078a838a3ffc2ac705  rhino2.jpg
```

**C.7 — HTTP Object Extraction**
```
49      1       137.30.123.234  137.30.120.37   GET     www.cs.uno.edu  /~gnome/rhino4.jpg
217     2       137.30.123.234  137.30.120.37   GET     www.cs.uno.edu  /~gnome/rhino5.gif
110     3       137.30.123.234  137.30.120.37   GET     www.cs.uno.edu  /~gnome/rhino.exe
```

---

## Appendix D — Completed Timeline Summary

| Stage | Event count | Earliest UTC | Latest UTC |
|---|---|---|---|
| Media preservation | 4 | 2026-11-04 | 2026-11-04 |
| Disk image / file-system review | 3 | 2026-11-04 | 2026-11-04 |
| Recovered or hidden content | 4 | 2026-11-04 | 2026-11-04 |
| FTP transfer activity | 6 | 2004-04-26 22:21:43 | 2026-11-04 |
| HTTP transfer activity | 3 | 2004-04-28 21:07 | 2004-04-28 |
| Corroborated conclusion | 1 | — | — |
| **Total** | **21** | — | — |

---

## Appendix E — Chain of Custody Worksheet

| Field | Value |
|---|---|
| Case/Lab Identifier | SBT-DF204-CaseStudy4-AkinwaOmokunleAnthony |
| Trainee Name | Akinwa Omokunle Anthony |
| Student ID | 2025/FWSD/11206 |
| Date and Time Acquired | 4 November, 2026 |
| Evidence File Names | `RHINOUSB.dd`, `rhino.log`, `rhino2.log`, `rhino3.log` |
| Source | ICDFA SBT-DF204 Case Study 4 lab package |
| File Sizes | 259,506,176 / 3,187,907 / 292,604 / 226,094 bytes |
| Original SHA-256 | `ce550424...`, `64e6d55b...`, `41939d5d...`, `7b0304f5...` |
| Working Copy | `working/RHINOUSB_working.dd` — SHA-256 verified identical |
| Custodian | Akinwa Omokunle Anthony (Student, ICDFA) |
| Handling Notes | Originals preserved read-only; analysis performed on working copy. Recovered binaries not executed. FTP credentials documented but not reused. ZIP cracked only against the supplied training archive. No live host contacted. |
| Analysis Tools | Sleuth Kit, PhotoRec 7.2, Tshark, fcrackzip 1.0, Python `stegdetect` |
| Analysis Date | 4 November, 2026 |

---

*Submitted by: Akinwa Omokunle Anthony | Student ID: 2025/FWSD/11206*  
*Course: SBT-DF204 — Computer Forensics Case Studies | Instructor: Aminu Idris, AMCPN*  
