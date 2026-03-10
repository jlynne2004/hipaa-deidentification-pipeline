# HIPAA De-Identification Pipeline & Toolkit

A healthcare data project demonstrating PHI and PII de-identification techniques using PostgreSQL, Python, and Streamlit. This project includes two components: a **PostgreSQL pipeline** implementing a secure de-identification architecture, and a **Streamlit toolkit** that allows users to upload any CSV, detect PHI/PII columns, score HIPAA compliance, de-identify data, and download a compliance report PDF.

---

## Project Overview

Healthcare organizations are required under HIPAA to de-identify patient data before it can be used for research or analytics. This project implements the **HIPAA Safe Harbor Method** — the standard that defines 18 specific identifiers that must be removed or masked to protect patient privacy.

This project demonstrates:
- **Masking** — SSN, phone number, PCP name
- **Redaction** — full name, address
- **Generalization** — patient first & last name truncated to first letter and '***', date of birth reduced to birth year, admission date reduced to year-month, ZIP code truncated to 3 digits
- **Tokenization** — patient, record, and insurance IDs replaced with SHA-256 hashed tokens
- **Role-Based Access Control (RBAC)** — a `data_analyst` role is granted access only to the de-identified analytics schema, with all access to the raw data schema revoked
- **Automated PHI/PII Detection** — keyword and regex-based column scanning across all 18 HIPAA Safe Harbor identifiers
- **Compliance Scoring** — 0–100 score with A–F grade and before/after comparison after de-identification

---

## Components

### 1. PostgreSQL Pipeline

A normalized two-schema architecture separating raw PHI from de-identified analytics views, with RBAC enforced at the database level.

### 2. Streamlit Toolkit

An interactive web app for uploading medical data CSVs, detecting PHI/PII, scoring compliance, applying de-identification transformations, and generating a downloadable compliance report PDF.

---

## Streamlit Toolkit

### Features

- **Upload any CSV** — works with any medical or patient data file
- **Automated PHI/PII Detection** — scans column names and data values using keyword matching and regex patterns across all 18 HIPAA Safe Harbor identifiers
- **Compliance Scoring** — scores your dataset 0–100 (A–F) based on detected PHI risk
- **Three De-Identification Modes:**
  - 🔄 **Generalize** — reduces precision while preserving analytical value (birth year, 3-digit ZIP, partial SSN)
  - 🛡️ **Full De-Identification** — HIPAA Safe Harbor compliant; fully removes or replaces all detected PHI
  - 🔍 **Audit** — scan only, no data changed; generates a compliance report to inform your de-identification strategy
- **Before/After Compliance Score** — see how your score improves after de-identification
- **Download De-Identified CSV** — export the transformed dataset
- **Compliance Report PDF** — branded one-page report with dataset summary, compliance scores, PHI detection results, and transformation descriptions

### How to Run the Toolkit

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Launch the app**
```bash
streamlit run hipaa_deidentification_toolkit.py
```

**3. Test with sample data**

Use any of the CSV files in this repo (`patients.csv`, `medical_records.csv`, `insurance.csv`) to test the toolkit without needing your own data.

> **Note:** For real patient data, run the toolkit locally rather than uploading sensitive PHI to a public deployment. The live demo is intended for use with sample or synthetic data only.

### Example Compliance Reports

See the `example_reports/` folder for sample PDF outputs across all three modes:
- Audit Mode (with logo)
- Generalize Mode (without logo)
- Full De-Identification Mode (with logo)

---

## PostgreSQL Pipeline Architecture

```
raw_data schema (restricted)        analytics schema (analyst-safe)
──────────────────────────────      ──────────────────────────────
raw_data.patients              →    analytics.patients (view)
raw_data.medical_records       →    analytics.medical_records (view)
raw_data.insurance             →    analytics.insurance (view)
```

The `raw_data` schema contains full PII and PHI. The `analytics` schema exposes only de-identified views. The `data_analyst` role cannot access `raw_data` at all — attempting to query it returns a permission denied error.

---

## HIPAA Safe Harbor Identifiers Addressed

| Identifier | Field | Treatment |
|---|---|---|
| Names | first_name, last_name | First initial only / REDACTED |
| Geographic data | address, city, zip | REDACTED / first initial / 3-digit ZIP |
| Dates | dob, admissions_date, policy_effective_date | Year only / Year-Month |
| Phone numbers | phone | Last 4 digits only |
| SSN | ssn | Last 4 digits only |
| Account numbers | member_id, group_number | Masked |
| Any other unique identifier | patient_id, record_id, insurance_id | SHA-256 hashed token |

---

## Tech Stack

- **PostgreSQL** — schema design, views, role-based access control
- **Python** — fake patient data generation, PHI detection engine, de-identification transformations
- **Faker** — realistic synthetic PII/PHI generation
- **Streamlit** — interactive web app interface
- **fpdf2** — compliance report PDF generation
- **pandas** — data loading, transformation, and export

---

## Files

| File | Description |
|---|---|
| `HIPAA_De-Identification_Pipeline.sql` | Full SQL script — schema creation, table creation, analytics views, and RBAC |
| `hipaa_deidentification_toolkit.py` | Streamlit toolkit — PHI detection, compliance scoring, de-identification engine, PDF report |
| `FakePatientData.py` | Python script to generate 50 fake patient records across three CSVs |
| `requirements.txt` | Python dependencies for the toolkit |
| `patients.csv` | Generated fake patient demographic data |
| `medical_records.csv` | Generated fake clinical records |
| `insurance.csv` | Generated fake insurance records |
| `example_reports/` | Sample compliance report PDFs for all three modes |

---

## How to Run the Pipeline

**1. Generate the fake data**
```bash
pip install faker
python FakePatientData.py
```
This outputs `patients.csv`, `medical_records.csv`, and `insurance.csv`.

**2. Run the SQL script in PostgreSQL**

Open `HIPAA_De-Identification_Pipeline.sql` in pgAdmin or psql and execute it. This will:
- Create the `raw_data` and `analytics` schemas
- Create all three raw tables
- Create the three de-identified analytics views
- Create the `data_analyst` role with restricted access

**3. Import the CSVs**
```sql
\copy raw_data.patients (first_name, last_name, ssn, dob, gender, address, city, state, zip, phone) 
FROM 'path/to/patients.csv' DELIMITER ',' CSV HEADER;

\copy raw_data.medical_records (patient_id, admissions_date, diagnosis, medication, pcp_name) 
FROM 'path/to/medical_records.csv' DELIMITER ',' CSV HEADER;

\copy raw_data.insurance (patient_id, insurance_provider, member_id, group_number, policy_effective_date) 
FROM 'path/to/insurance.csv' DELIMITER ',' CSV HEADER;
```

**4. Verify role-based access control**
```sql
-- Switch to analyst role
SET ROLE data_analyst;

-- This should return: ERROR: permission denied for schema raw_data
SELECT * FROM raw_data.patients;

-- This should return de-identified data successfully
SELECT * FROM analytics.patients;

-- Reset back to superuser
RESET ROLE;
```

---

## Key Concepts Demonstrated

**Why separate schemas?** The schema separation acts as a security boundary. Raw data lands in `raw_data` and never leaves it — analysts only ever interact with the `analytics` layer.

**Why generalize dates rather than redact them?** Dates carry analytical value. Reducing DOB to birth year preserves the ability to analyze age demographics while eliminating the precision needed to re-identify an individual — this is the HIPAA Safe Harbor standard.

**Why truncate ZIP codes to 3 digits?** HIPAA Safe Harbor requires ZIP codes to be reduced to the first 3 digits, and further suppressed if the region contains fewer than 20,000 people, to prevent geographic re-identification.

**Why hash IDs instead of removing them?** Hashed tokens allow analysts to join and aggregate across tables without exposing real identifiers. The hash is deterministic — the same patient always gets the same token — but it cannot be reversed to reveal the original ID.

**Why offer multiple de-identification modes?** Different use cases require different levels of de-identification. Generalize preserves more analytical value for internal research; Full De-Identification meets Safe Harbor standards for external sharing; Audit supports compliance assessment before committing to a transformation strategy.

---

*All patient data in this project is entirely fictional and was generated using the Faker library. No real patient information was used.*
