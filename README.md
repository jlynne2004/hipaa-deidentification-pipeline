# HIPAA De-Identification Pipeline

A complete, end-to-end toolkit for detecting, scoring, and removing Protected Health Information (PHI) from medical datasets by implementing the HIPAA Safe Harbor method.

---

## Overview

Healthcare organizations routinely need to share patient data for analytics, research, and reporting. Doing so safely requires removing or masking the 18 HIPAA-defined identifiers that constitute PHI. This project has two components: an interactive Streamlit web application for PHI detection and de-identification, and a PostgreSQL database architecture demonstrating role-based access control (RBAC) to prevent unauthorized exposure of raw data.

**The pipeline covers three layers of data governance:**

1. **Detection** — Automatically scan any CSV for PHI using keyword matching and regex pattern analysis
2. **Scoring** — Grade your dataset on a compliance scale (A–F) before and after de-identification
3. **Transformation** — Apply one of three de-identification strategies appropriate to your use case
4. **Reporting** — Generate branded PDF compliance reports documenting what was found and what was done

---

## Features

### PHI Detection
- Detects all 18 HIPAA Safe Harbor identifiers across column names and data values
- Two-layer detection: keyword matching on column headers + regex pattern scanning on row values
- Confidence scoring per column (High / Medium / Low) based on match strength
- Covers names, SSNs, dates, phone numbers, addresses, ZIP codes, emails, IDs, IP addresses, and more

### Compliance Scoring
- Letter grades (A–F) with before/after comparison
- Score formula accounts for count and severity of detected PHI columns
- Visual improvement metrics in generated reports

### De-Identification Modes

| Mode | Description | Best For |
|------|-------------|----------|
| **Audit** | Scan only, no data modified | Understanding current risk |
| **Generalize** | Reduce precision while preserving analytical value | Internal cross-team sharing |
| **Full De-Identification** | Complete removal per HIPAA Safe Harbor | Research, public reporting |

**Generalize Mode** preserves last 4 digits of SSNs and phone numbers, year of dates, name initials, and 3-digit ZIP prefixes — retaining demographic signal for analysis while removing direct identifiers.

**Full De-ID Mode** maximizes privacy: names fully redacted, IDs replaced with SHA-256 tokens, addresses removed, and all dates reduced to year only.

### Compliance Reports
- PDF reports generated with `fpdf2`
- Configurable branding (organization name, logo)
- Sections: dataset summary, PHI detection table, compliance scores (before/after), transformations applied, legal disclaimer
- Color-coded letter grades

### Database RBAC Architecture
- PostgreSQL two-schema design separating `raw_data` (restricted) from `analytics` (de-identified views)
- `data_analyst` role has SELECT-only access to analytics views with zero access to raw source tables
- Demonstrates production-grade data governance for teams that need both security and accessibility

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Web UI | [Streamlit](https://streamlit.io/) |
| Data Processing | [Pandas](https://pandas.pydata.org/) |
| PDF Generation | [fpdf2](https://py-pdf.github.io/fpdf2/) |
| Fake Data Generation | [Faker](https://faker.readthedocs.io/) |
| Hashing / Tokenization | Python `hashlib` (SHA-256) |
| Database Layer | PostgreSQL |
| Language | Python 3.x |

---

## How to Run

### Prerequisites

```bash
pip install streamlit pandas fpdf2 faker
```

### Step 1 — Generate Sample Data (Optional)

The repository includes pre-generated sample data in `data/raw/`. To regenerate it:

```bash
python FakePatientData.py
```

This creates three related CSVs in `data/raw/`:
- `patients.csv` — 50 patients with demographics and PII
- `medical_records.csv` — Medical visit records linked to patients
- `insurance.csv` — Insurance membership and policy data

### Step 2 — Launch the Application

```bash
streamlit run hipaa_deidentification_toolkit.py
```

Open your browser to `http://localhost:8501`.

### Step 3 — Use the Toolkit

1. Upload any CSV containing medical/patient data
2. Review the PHI detection results and compliance grade
3. Select a de-identification mode
4. Download the de-identified CSV and/or PDF compliance report

### Optional — PostgreSQL Setup

To explore the database RBAC layer:

```bash
psql -U postgres -f HIPAA_De-Identification_Pipeline.sql
```

This creates:
- `raw_data` schema with patient, medical record, and insurance tables
- `analytics` schema with de-identified views
- A `data_analyst` role scoped to analytics-only access

---

## Folder Structure

```
hipaa_deidentification_pipeline/
│
├── hipaa_deidentification_toolkit.py    # Main Streamlit application
├── FakePatientData.py                   # Fake patient data generator
├── HIPAA_De-Identification_Pipeline.sql # PostgreSQL schema and RBAC views
│
├── data/
│   ├── raw/                             # Source data with PHI (for demo only)
│   │   ├── patients.csv
│   │   ├── medical_records.csv
│   │   └── insurance.csv
│   └── deidentified/                    # De-identified output files
│       ├── patients_deidentified.csv
│       ├── medical_records_deidentified.csv
│       └── insurance_deidentified.csv
│
├── example_reports/                     # Sample PDF compliance reports
│   ├── EXAMPLE Audit Mode Compliance Report w Logo.pdf
│   ├── EXAMPLE Full De-Identification Mode Compliance Report w Logo.pdf
│   ├── EXAMPLE Full De-Identification Mode Compliance Report w Logo and Conditional Formatting.pdf
│   └── EXAMPLE Generalize Mode Compliance Report without Logo.pdf
│
└── assets/                              # Documentation images
    ├── 01_set_role_data_analyst.png
    └── 02_permission_denied_raw_data.png
```

---

## De-Identification Examples

**Input (raw patient record):**
```
patient_id, first_name, last_name, ssn,         dob,        zip,   phone
1,          James,      Lopez,     134-33-6634,  1999-11-24, 51751, (237) 922-6065
```

**Generalize Mode output:**
```
patient_id, first_name, last_name, masked_ssn,   birth_year, zip_region, masked_phone
c4ca4238,   J***,       L***,      XXX-XX-6634,  1999,       517,        ###-###-6065
```

**Full De-Identification Mode output:**
```
patient_token,                                   first_name, last_name, masked_ssn,   birth_year, zip_region, masked_phone
c4ca4238a0b923820dcc509a6f75849b...,            REDACTED,   REDACTED,  XXX-XX-6634,  1999,       517,        ###-###-6065
```

---

## HIPAA Safe Harbor Reference

This toolkit targets the 18 PHI identifiers defined under 45 CFR §164.514(b):

Names · Geographic data smaller than state · Dates (except year) · Phone numbers · Fax numbers · Email addresses · Social Security numbers · Medical record numbers · Health plan beneficiary numbers · Account numbers · Certificate/license numbers · Vehicle identifiers · Device identifiers · URLs · IP addresses · Biometric identifiers · Full-face photographs · Any other unique identifying number or code

---

## Disclaimer

This toolkit is intended for educational and demonstration purposes. The sample data is entirely synthetic, generated using the Faker library with no connection to real individuals. This tool does not constitute legal compliance advice. Organizations handling real PHI should consult a qualified HIPAA compliance officer.
