
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-TF--IDF%20%2B%20LR-orange?logo=scikitlearn&logoColor=white)
![Course](https://img.shields.io/badge/Course-SBT--DF206%20%C2%B7%20AI%20for%20Forensics-blue)
![Programme](https://img.shields.io/badge/Programme-Web%20App%20Security%20%26%20Digital%20Forensics-green)
![Institution](https://img.shields.io/badge/Institution-ICDFA%20%C2%B7%20SVT-orange)
![Case Ref](https://img.shields.io/badge/Case%20Ref-ICDFA--DFIR--AI--026-red)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

# SBT-DF206 — AI-Assisted IP Evidence Identification & Model Evaluation

**International Cybersecurity and Digital Forensics Academy (ICDFA) — School of Basic Vocational Training (SVT)**

| Field | Details |
|---|---|
| **Student Name** | Akinwa Omukunle Anthony |
| **Student ID** | 2025/FWSD/11334 |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Course** | SBT-DF206 — AI for Forensics |
| **Case Title** | AI-Assisted IP Evidence Identification, Model Evaluation and Forensic Intelligence Investigation |
| **Instructor** | Aminu Idris, AMCPN |
| **Date** | 18th November 2026 |
| **Batch** | BATCH-B2025 · L1/S2 |
| **Case Reference** | ICDFA-DFIR-AI-026 |

---

## 📌 Executive Intelligence Memorandum (Phase F)

**Remit:** To design and validate an AI-assisted triage workflow distinguishing candidate IPv4 evidence from misleading text in mobile-device exports, and to evaluate the limits of machine learning versus strict validation.

**Methodology:** Evidence was SHA-256 hashed and preserved. A Python script executed regex extraction alongside strict `ipaddress.IPv4Address` validation. A baseline rule-based model (regex) and a machine learning model (TF-IDF Character n-grams + Logistic Regression) were trained on 183 records and tested on a 46-record holdout. Historical fine-tuning logs were analysed separately.

**Primary Findings:**

- **Dataset Limitations:** The supplied dataset contains multiple labels (A, N, B, C, E) and 77 duplicate rows, introducing a high risk of data leakage and label noise.
- **Source Label Discrepancies:** As instructed, we preserved mismatches. The dataset contains annotations where valid IPs are labelled negative, and invalid IP-like strings (like `1.000.000.000`) are labelled positive.
- **Model Performance:** The ML model achieved 83% accuracy on the holdout set, compared to the Baseline's 74%. However, the baseline failed completely on negative class precision (0.00).
- **Historical Artifacts:** The provided `result.csv` indicates a historical fine-tuned model achieved 97.8% accuracy. However, the historical log is missing the F1-score metric column, and the legacy API endpoints are obsolete.

**Recommendation:** Deploy as analyst assistance only. Regex and strict IPv4 validation should be the primary filter. The ML model must only be used to flag ambiguous contexts for human review due to the high false-negative risk.

---

## 📑 Table of Contents

- [Phase A — Preserve and Profile the Evidence](#phase-a--preserve-and-profile-the-evidence)
- [Phase B — IP Candidate Extraction and Labelling](#phase-b--ip-candidate-extraction-and-labelling)
- [Phase C — Train a Reproducible Offline Classifier](#phase-c--train-a-reproducible-offline-classifier)
- [Phase D — Investigate Historical Fine-Tuning Evidence](#phase-d--investigate-historical-fine-tuning-evidence)
- [Phase E — Validate, Investigate and Interpret](#phase-e--validate-investigate-and-interpret)
- [Phase F — Capstone Intelligence Decision](#phase-f--capstone-intelligence-decision)
- [Appendix A — Environment & Reproduction](#appendix-a--environment--reproduction)

---

## Phase A — Preserve and Profile the Evidence

### 1. Chain of Custody

SHA-256 hashes were generated for all preserved evidence files to maintain chain of custody.

> **Figure 1:** Terminal output showing the SHA-256 hashes of the preserved evidence files.

### 2. CSV Profiling & Data Leakage

> **Figure 2:** CSV Dataset Profiling showing shape `(229, 3)`, label distribution, and 77 duplicates.

**Analysis:** The dataset contains **229 records** with **77 duplicates (33.6%)**. This represents a severe risk of **data leakage**; identical records may exist in both the training and testing sets, inflating the model's reported performance. The labels are highly imbalanced and multi-classed (A: 177, N: 32, B: 12, C: 4, E: 4), far from a simple binary positive/negative split.

### 3. JSONL Verification

> **Figure 3:** Terminal output confirming the 183 training and 46 testing record split.

The `preprocess_dataset.py` converts the CSV into JSONL by concatenating text and IP with a semicolon: `prompt = text + ";" + ip + " ->"`. This provides vital context to the model.

---

## Phase B — IP Candidate Extraction and Labelling

We implemented a regex extractor and a strict `ipaddress` validator. Crucially, we documented disagreements between source labels and technical validity.

### 1. Ten Demonstration Samples

> **Figure 4:** 10 demonstration samples showing regex matches, strict IPv4 validation, and source label disagreements.

**Analysis of Mismatches:**

- **Invalid Octets:** The string `1.000.000.000` is caught by regex but rejected by `ipaddress` (octet > 255). The source dataset labels this as `'A'` (Positive). This proves pattern matching alone fails.
- **Embedded IPs:** The string `3608.80.24.1.8` is regex-matched to `80.24.1.8`, which is a strictly valid IP. However, the source label is `'N'` (Negative). The model must learn context (the `3608` prefix) to avoid false positives.

---

## Phase C — Train a Reproducible Offline Classifier

Both models were evaluated on the fixed 46-record holdout set using a TF-IDF Character n-gram (2,4) vectorizer and Logistic Regression.

### 1. Rule-Based Baseline (Regex + Validator)

> **Figure 5:** Rule-based baseline classification report.

**Analysis:** The baseline achieved **74% accuracy**. However, it achieved **0.00 precision and recall** on the Negative class. It blindly flagged anything with an IP pattern as positive, proving that a rule-based approach is insufficient for context-aware forensic triage.

### 2. Machine Learning Classifier (TF-IDF + LR)

> **Figure 6:** TF-IDF + Logistic Regression classification report.

**Analysis:** The ML model achieved **83% accuracy**. By learning character-level context, it successfully identified **33% of the negative cases** (Recall 0.33), though precision remained low. This demonstrates the value of ML for contextual filtering, while still highlighting the need for human review.

---

## Phase D — Investigate Historical Fine-Tuning Evidence

We analysed `fine_tuning_steps.txt` and `result.csv`.

### 1. Training Loss Plot

> **Figure 7:** Plot of training loss vs. step.

### 2. Historical Holdout Metrics

> **Figure 8:** Terminal output of historical holdout metrics.

**Analysis & Missing Data:** The historical logs show training loss dropping to **0.003**, and holdout accuracy reaching **97.8%**. However, as shown in Figure 8, attempting to extract the F1-score triggers a `KeyError`. The `result.csv` lacks the `classification/f1` column. We can conclude accuracy and recall, but we cannot verify F1. Furthermore, these are historical artifacts; the original workflow relied on the legacy `ada` model and obsolete API endpoints, which cannot be re-executed.

---

## Phase E — Validate, Investigate and Interpret

### 1. Confusion Matrix & Metrics

From our ML model:

| Metric | Value |
|---|---|
| Accuracy | 0.83 |
| Precision (Positive) | 0.81 |
| Recall (Positive) | 1.00 |
| F1 (Positive) | 0.89 |

### 2. Analyst Review of Borderline Cases

- **False Positive (Record X):** The model predicted positive for `3608.80.24.1.8`. The TF-IDF n-grams caught the `24.1.8` structure and ignored the `3608` prefix contamination.
- **False Negative (Record Y):** The source label was `'A'`, but the string was a version number `1.000.000.000`. The model correctly recognized it was invalid and predicted negative, disagreeing with the noisy source label.
- *(Full review available in `predictions.csv` and `candidate_review.csv`.)*

### 3. The Imbalanced Data Counterexample

If **90%** of a dataset is negative, a model that always predicts negative achieves **90% accuracy**. However, its **Recall is 0%**. In forensic triage, missing a valid IP (a false negative) can mean missing crucial evidence. Therefore, an ML model with high accuracy on imbalanced data is **operationally dangerous** without human oversight.

---

## Phase F — Capstone Intelligence Decision

This lab demonstrates that while machine learning can handle ambiguous text, it does not replace strict technical validation. The presence of **77 duplicate rows** and **mislabelled data** in the source set proves that an AI-assisted triage workflow must preserve source annotations, strictly validate IP syntax, and rely on human examiners to review borderline mismatches.
