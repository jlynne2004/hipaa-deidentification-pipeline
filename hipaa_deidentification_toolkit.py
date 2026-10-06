# Streamlit App to Streamline the De-Identification Process for Medical Data
# Features:
# - Upload medical data CSV
# - Auto-detect PII/PHI columns (HIPAA Safe Harbor 18 identifiers)
# - Score data for potential PHI risk (A-F)
# - Suggest improvements per flagged column
# - De-identify data with one click
# - Show before/after PHI risk score
# - Download de-identified CSV
# - Download PHI risk / de-identification report PDF

# Libraries
import hashlib
import io
import re
from datetime import datetime

import streamlit as st
import pandas as pd

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

# Add temporarily for verifying fpdf installation in Streamlit Cloud; can remove after confirming it works in the deployed environment.
# st.write(f"FPDF value: {FPDF}")
# import sys
# st.write(sys.executable)

# ---------------------------------------------------------------------------
# PII/PHI Detection — HIPAA Safe Harbor 18 Identifiers
# ---------------------------------------------------------------------------

# Maps each HIPAA identifier category to column-name keywords (case-insensitive).
PHI_COLUMN_KEYWORDS = {
    "Name":                ["name", "first_name", "last_name", "fname", "lname", "full_name", "patient_name", "physician", "pcp", "doctor", "provider"],
    "Geographic":          ["address", "street", "addr", "city", "zip", "postal", "county", "district", "location"],
    "Date":                ["dob", "date_of_birth", "birthdate", "birth_date", "admissions_date", "admission_date",
                            "discharge_date", "dod", "date_of_death", "service_date", "policy_effective_date",
                            "date", "timestamp"],
    "Phone/Fax":           ["phone", "telephone", "cell", "mobile", "fax", "contact_number"],
    "Email":               ["email", "email_address", "e_mail"],
    "SSN":                 ["ssn", "social_security", "social_security_number", "sin"],
    "Medical Record #":    ["mrn", "medical_record", "record_number", "record_id", "chart_number"],
    "Health Plan ID":      ["member_id", "beneficiary", "plan_id", "group_number", "group_id", "insurance_id"],
    "Account Number":      ["account_number", "account_id", "account_no", "acct"],
    "Certificate/License": ["license", "certificate", "cert_number", "license_number"],
    "Vehicle ID":          ["vin", "vehicle_id", "license_plate", "plate_number"],
    "Device ID":           ["device_id", "device_serial", "serial_number", "imei"],
    "URL":                 ["url", "website", "web_address", "webpage"],
    "IP Address":          ["ip_address", "ip_addr"],
    "Biometric":           ["fingerprint", "biometric", "voice_print", "retina"],
    "Photo":               ["photo", "image", "photograph", "picture", "face"],
    "Unique ID":           ["patient_id", "unique_id", "uid", "guid", "subject_id"],
    "Age":                 ["age", "patient_age"],
}

# Maps each HIPAA identifier category to a regex that matches its data pattern.
# Patterns are applied to a sample of non-null string values from each column.
PHI_REGEX_PATTERNS = {
    "SSN":        re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    "Phone/Fax":  re.compile(r"^(\(\d{3}\)\s?\d{3}-\d{4}|\d{3}[-.\s]\d{3}[-.\s]\d{4}|\+?1?\s?\d{10})$"),
    "Email":      re.compile(r"^[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}$"),
    "Date":       re.compile(r"^(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}|\d{1,2}-\d{1,2}-\d{4})$"),
    "ZIP":        re.compile(r"^\d{5}(-\d{4})?$"),
    "IP Address": re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
    "URL":        re.compile(r"^https?://\S+$"),
}


def _keyword_hits(col_name: str) -> list[str]:
    """Return PHI categories whose keywords appear in col_name."""
    col_lower = col_name.lower()
    hits = []
    for category, keywords in PHI_COLUMN_KEYWORDS.items():
        if category == "Age":
            normalized = re.sub(r"[^a-z0-9]+", "_", col_lower).strip("_")
            if normalized in keywords:
                hits.append(category)
        elif any(kw in col_lower for kw in keywords):
            hits.append(category)
    return hits


def _regex_hits(series: pd.Series) -> list[str]:
    """Return PHI categories whose regex matches ≥50% of a column's sample values."""
    # Work with a sample of up to 50 non-null string representations
    sample = series.dropna().astype(str).head(50)
    if sample.empty:
        return []

    hits = []
    for category, pattern in PHI_REGEX_PATTERNS.items():
        match_rate = sample.apply(lambda v: bool(pattern.match(v.strip()))).mean()
        if match_rate >= 0.5:
            hits.append(category)
    return hits


def score_phi_compliance(phi_results: dict) -> dict:
    """
    Calculate a heuristic PHI Risk Score based on detection results.

    This is a toolkit-specific screening metric, not an official HIPAA compliance score.

    Deductions:
      - 10 points per High confidence flagged column
      -  5 points per Medium confidence flagged column

    Returns a dict with score (0-100), letter grade, and a breakdown.
    """
    high_count   = sum(1 for i in phi_results.values() if i["flagged"] and i["confidence"] == "High")
    medium_count = sum(1 for i in phi_results.values() if i["flagged"] and i["confidence"] == "Medium")
    deductions   = (high_count * 10) + (medium_count * 5)
    score        = max(0, 100 - deductions)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    if high_count >= 5 or deductions >= 100:
        risk_level = "Critical"
    elif high_count >= 2 or deductions >= 50:
        risk_level = "High"
    elif high_count >= 1 or deductions >= 20:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    return {
        "score":        score,
        "grade":        grade,
        "risk_level":   risk_level,
        "high_count":   high_count,
        "medium_count": medium_count,
        "deductions":   deductions,
    }


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    return "F"


def compute_after_compliance(mode: str, transformed_df: pd.DataFrame) -> dict | None:
    """
    Re-scan transformed values for recognizable PHI patterns and return the
    toolkit's residual PHI Risk Score. Column names are intentionally ignored
    during verification because a column may still be named ``ssn`` even after
    its values have been redacted.

    This verification is heuristic and does not certify HIPAA compliance.
    """
    if mode == "Audit":
        return None

    residual_results = detect_phi_columns(transformed_df, values_only=True)
    result = score_phi_compliance(residual_results)
    result["residual_results"] = residual_results
    return result


def detect_phi_columns(df: pd.DataFrame, values_only: bool = False) -> dict:
    """
    Scan every column in df for HIPAA PHI using keyword and regex heuristics.

    values_only=True skips column-name keyword matching and evaluates only
    cell values via regex. Use this when scoring already-transformed data so
    that masked columns (e.g. 'ssn' containing 'XXX-XX-6634') are not
    penalised purely because of their name.

    Returns a dict keyed by column name:
        {
            "col_name": {
                "phi_types":  [...],      # PHI categories detected
                "methods":    [...],      # "keyword" and/or "regex"
                "confidence": "High" | "Medium" | "Low",
                "flagged":    True | False
            }
        }
    """
    results = {}

    for col in df.columns:
        kw_hits  = [] if values_only else _keyword_hits(col)
        rgx_hits = _regex_hits(df[col])

        # Five-digit values are ambiguous (e.g., CPT/procedure codes).
        # Require postal context before accepting a regex-only ZIP match.
        if "ZIP" in rgx_hits and not any(k in col.lower() for k in ("zip", "postal", "postcode")):
            rgx_hits = [x for x in rgx_hits if x != "ZIP"]

        all_types = list(dict.fromkeys(kw_hits + rgx_hits))
        methods   = (["keyword"] if kw_hits else []) + (["regex"] if rgx_hits else [])

        if kw_hits and rgx_hits:
            confidence = "High"
        elif kw_hits or rgx_hits:
            confidence = "Medium"
        else:
            confidence = "Low"

        results[col] = {
            "phi_types":  all_types,
            "methods":    methods,
            "confidence": confidence,
            "flagged":    bool(all_types),
        }

    return results

# ---------------------------------------------------------------------------
# De-Identification Mode Selector
# ---------------------------------------------------------------------------

def select_deid_mode(phi_types: list[str]) -> str:
    """
    Allow the user to select a de-identification mode based on what level of security they need.
    """
    st.write("**Select a de-identification mode:**")
    st.write(f"*Detected PHI types: {', '.join(phi_types)}*")
    st.write("")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔄 Generalize", use_container_width=True, key="mode_generalize"):
            st.session_state["selected_deid_mode"] = "Generalize"
            st.info("Selected: Generalize\nReduces precision while preserving analytical value. Best for internal cross-department sharing.")
            return "Generalize"

    with col2:
        if st.button("🛡️ Safe Harbor De-Identification", use_container_width=True, key="mode_full"):
            st.session_state["selected_deid_mode"] = "Safe Harbor De-Identification"
            st.info("Selected: Safe Harbor De-Identification\nApplies conservative HIPAA Safe Harbor transformations to PHI detected by the toolkit. Output should still be reviewed for undetected identifiers before use or disclosure.")
            return "Safe Harbor De-Identification"

    # Future V2 modes (commented):
    # with third column:
    #     if st.button("🔒 Mask", use_container_width=True, key="mode_mask"):
    #         st.session_state["selected_deid_mode"] = "Mask"
    #         st.info("Selected: Mask\nObscure sensitive values while preserving format (e.g. SSN → XXX-XX-1234).")
    #         return "Mask"

    # with optional hash / future column:
    #     if st.button("🔗 Hash", use_container_width=True, key="mode_hash"):
    #         st.session_state["selected_deid_mode"] = "Hash"
    #         st.info("Selected: Hash\nApply irreversible hashes to flagged values.")
    #         return "Hash"

    if st.button("🔍 Audit", use_container_width=True, key="mode_audit"):
        st.session_state["selected_deid_mode"] = "Audit"
        st.info("Selected: Audit - Scan only; no data changed\nAnalyzes your data and generates a compliance report that helps you understand your current HIPAA risk before deciding how to de-identify your data.")
        return "Audit"

    if "selected_deid_mode" in st.session_state:
        return st.session_state["selected_deid_mode"]

    return "Safe Harbor De-Identification"  # Default mode
# ---------------------------------------------------------------------------
# De-Identification
# ---------------------------------------------------------------------------

def _transform_value(value, phi_types: list[str], confidence: str, mode: str = "Safe Harbor De-Identification", col_name=""):
    """
    Apply the correct de-identification rule to a single cell value based on the selected mode.
    
    Modes:
    - Generalize: Preserve analytical value, reduce precision
    # - Mask: Hide sensitive values but keep format (planned V2)
    # - Hash: Irreversible SHA-256 hashing (planned V2)
    - Safe Harbor De-Identification: conservative transformations aligned to HIPAA Safe Harbor identifier-removal rules
    - Audit: No value change; reporting/audit only
    """
    if pd.isna(value):
        return value

    val = str(value).strip()

    # --- AUDIT MODE ---
    # In Audit mode, we do not transform any values. This function will simply return the original value.
    if mode == "Audit":
        return value

    # --- GENERALIZE MODE ---
    if mode == "Generalize":
        # Specific identifier types take precedence over broad Name/Geographic matches.
        if "Photo" in phi_types:
            return "[IMAGE]"
        if "Biometric" in phi_types:
            return "[BIOMETRIC]"
        if "URL" in phi_types:
            return "[URL]"
        if "IP Address" in phi_types:
            parts = val.split(".")
            return f"{parts[0]}.{parts[1]}.x.x" if len(parts) == 4 and all(p.isdigit() for p in parts) else "[IP]"
        if "Email" in phi_types:
            if "@" in val:
                local, domain = val.rsplit("@", 1)
                return f"{(local[:1] or 'x').lower()}***@{domain}"
            return "[EMAIL]"
        if "Vehicle ID" in phi_types or "Device ID" in phi_types or "Certificate/License" in phi_types:
            return hashlib.sha256(val.encode()).hexdigest()[:12]
        if "SSN" in phi_types:
            digits = re.sub("[^0-9]", "", val)
            return f"XXX-XX-{digits[-4:]}" if len(digits) >= 4 else "XXX-XX-XXXX"
        if "Phone/Fax" in phi_types:
            digits = re.sub("[^0-9]", "", val)
            return f"###-###-{digits[-4:]}" if len(digits) >= 4 else "###-###-####"
        if "Date" in phi_types:
            year_match = re.search(r"(19|20)[0-9]{2}", val)
            return year_match.group(0) if year_match else "XXXX"
        if "Name" in phi_types:
            return f"{val[0].upper()}***" if val else "***"
        if "ZIP" in phi_types:
            return val[:3]
        if "Geographic" in phi_types:
            if any(kw in col_name.lower() for kw in ["address", "street", "addr"]):
                return "REDACTED"
            if any(kw in col_name.lower() for kw in ["city", "town", "municipality"]):
                return val  # preserve city in Generalize mode
            return "REDACTED"
        if any(t in phi_types for t in ("Unique ID", "Health Plan ID", "Medical Record #", "Account Number")):
            return hashlib.sha256(val.encode()).hexdigest()[:12]  # Deterministic pseudonymous ID
        return value

    # --- MASK MODE ---
    # (planned for V2: leave here as a comment reference for future rollout)
    # if mode == "Mask":
    #     if "SSN" in phi_types:
    #         digits = re.sub("[^0-9]", "", val)
    #         return f"XXX-XX-{digits[-4:]}" if len(digits) >= 4 else "XXX-XX-XXXX"
    #     if "Phone/Fax" in phi_types:
    #         digits = re.sub("[^0-9]", "", val)
    #         return f"###-###-{digits[-4:]}" if len(digits) >= 4 else "###-###-####"
    #     if "Date" in phi_types:
    #         return "1900-01-01"
    #     if "Name" in phi_types:
    #         return "X***" if val else "***"
    #     if "ZIP" in phi_types:
    #         return "XXX##"
    #     if "Geographic" in phi_types:
    #         return "[LOCATION]"
    #     if any(t in phi_types for t in ("Unique ID", "Health Plan ID", "Medical Record #", "Account Number")):
    #         return "[ID]"
    #     if confidence == "High":
    #         return "[MASKED]"
    #     return value

    # (Redact mode removed from V1; implemented via database-level controls or future feature.)

    # --- HASH MODE ---
    # (planned for V2: keep as comment reference)
    # if mode == "Hash":
    #     if any(phi_types) or confidence == "High":
    #         return hashlib.sha256(val.encode()).hexdigest()
    #     return value

    # --- SAFE HARBOR DE-IDENTIFICATION MODE (Default) ---
    # This mode is intentionally conservative. It removes detected direct
    # identifiers rather than preserving analytically useful fragments.

    # Direct identifiers: remove completely.
    if any(t in phi_types for t in (
        "SSN", "Phone/Fax", "Email", "Name", "Medical Record #",
        "Health Plan ID", "Account Number", "Certificate/License",
        "Vehicle ID", "Device ID", "URL", "IP Address", "Biometric",
        "Photo", "Unique ID"
    )):
        return "REDACTED"

    # Ages over 89 must be aggregated as 90+. Ages 89 and under may remain.
    if "Age" in phi_types:
        try:
            age = int(float(val))
            return "90+" if age > 89 else value
        except (TypeError, ValueError):
            return "REDACTED"

    # Dates: retain year only, except DOBs implying age >89 are aggregated.
    if "Date" in phi_types:
        year_match = re.search(r"(19|20)[0-9]{2}", val)
        if not year_match:
            return "REDACTED"
        year = int(year_match.group(0))
        if any(kw in col_name.lower() for kw in ("dob", "date_of_birth", "birthdate", "birth_date")):
            if datetime.now().year - year > 89:
                return "90+"
        return str(year)

    # Geographic subdivisions smaller than a state are removed. For ZIP codes,
    # Safe Harbor permits some 3-digit prefixes only when current population
    # criteria are met. Because this standalone toolkit does not bundle a
    # current Census population crosswalk, it takes the conservative route and
    # suppresses the ZIP rather than making an unsupported population claim.
    if "ZIP" in phi_types:
        return "000"
    if "Geographic" in phi_types:
        return "REDACTED"

    # Catch-all for any remaining detected PHI.
    if phi_types or confidence == "High":
        return "REDACTED"

    return value



def deidentify_dataframe(df: pd.DataFrame, phi_results: dict, mode: str = "Safe Harbor De-Identification") -> pd.DataFrame:
    """
    Return a copy of df with all flagged PHI columns transformed.
    Unflagged columns are passed through unchanged.
    
    Args:
        df: The DataFrame to de-identify
        phi_results: PHI detection results from detect_phi_columns()
        mode: De-identification mode (Generalize, Safe Harbor De-Identification, or Audit)
    """
    deidentified = df.copy()
    for col, info in phi_results.items():
        if not info["flagged"]:
            continue
        deidentified[col] = df[col].apply(
            lambda v, types=info["phi_types"], conf=info["confidence"], m=mode:
                _transform_value(v, types, conf, m, col)
        )
    return deidentified


def _describe_transformation(phi_types: list[str], mode: str, col_name: str) -> str:
    if mode == "Audit":
        if "SSN" in phi_types:
            return "SSN detected. Safe Harbor requires removal of Social Security numbers."
        if "Name" in phi_types:
            return "Name detected. Safe Harbor requires removal of names."
        if "Date" in phi_types:
            return "Date detected. Safe Harbor generally permits year-only treatment; ages over 89 and related date information require 90+ aggregation."
        if "Phone/Fax" in phi_types:
            return "Phone/Fax detected. Safe Harbor requires removal of telephone and fax numbers."
        if "ZIP" in phi_types:
            return "ZIP detected. Safe Harbor permits an eligible 3-digit prefix only when the population rule is satisfied; otherwise use 000."
        if "Geographic" in phi_types:
            return "Geographic data detected. Safe Harbor requires removal of geographic subdivisions below state, subject to the ZIP rule."
        return "Potential PHI detected. Review the identifier against Safe Harbor requirements and remove it before disclosure when applicable."

    if mode == "Generalize":
        details = []
        if "Photo" in phi_types:
            details.append("Replace image reference with [IMAGE]")
        if "Biometric" in phi_types:
            details.append("Replace biometric identifier with [BIOMETRIC]")
        if "URL" in phi_types:
            details.append("Replace URL with [URL]")
        if "IP Address" in phi_types:
            details.append("Generalize IP to first two octets")
        if "Email" in phi_types:
            details.append("Mask email local-part while retaining domain")
        if any(t in phi_types for t in ("Certificate/License", "Vehicle ID", "Device ID")):
            details.append("Replace identifier with deterministic truncated hash")
        if "SSN" in phi_types:
            details.append("Generalize SSN to partial (e.g., XXX-XX-1234)")
        if "Phone/Fax" in phi_types:
            details.append("Generalize phone number to area code or masked form")
        if "Date" in phi_types:
            details.append("Generalize date to year only")
        if "Name" in phi_types:
            details.append("Generalize name to initial + ***")
        if "ZIP" in phi_types:
            details.append("Generalize ZIP to first 3 digits")
        if "Geographic" in phi_types:
            details.append("Generalize geographic to reduced precision or REDACTED")
        if any(t in phi_types for t in ("Unique ID", "Health Plan ID", "Medical Record #", "Account Number")):
            details.append("Generalize IDs using truncated hash")
        return ", ".join(details) if details else "Generalize all flagged values"

    # Mask and Hash are reserved for V2; currently this function returns coarser guidance.
    # if mode == "Mask":
    #     return "Mask detected PHI values based on type while preserving format"
    # if mode == "Hash":
    #     return "SHA-256 hashing for all flagged PHI columns"

    if mode == "Safe Harbor De-Identification":
        return "Conservative Safe Harbor transformation applied to detected PHI; manual review is still required for undetected identifiers"

    return "No transformation defined for selected mode"


def create_compliance_report_pdf(
    file_name: str,
    row_count: int,
    col_count: int,
    flagged: dict,
    clean: dict,
    compliance: dict,
    mode: str,
    before_compliance: dict,
    after_compliance: dict | None,
    logo_bytes: bytes | None,
) -> bytes:
    if FPDF is None:
        raise RuntimeError("fpdf library is required. Install via 'pip install fpdf2'.")

    pdf = FPDF(format="letter")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
   
    if logo_bytes:
        try:
            logo_width = 25
            logo_x = pdf.w - pdf.r_margin - logo_width
            logo_y = 8
            pdf.image(io.BytesIO(logo_bytes), x=logo_x, y=logo_y, w=logo_width)
        except Exception:
            pass

    NAVY_BLUE = (11, 11, 69)
    BLACK = (0, 0, 0)

    pdf.set_text_color(*NAVY_BLUE)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 6, "Jess Hayden Consulting", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, "Turning Chaos into Clarity", ln=True)
    pdf.ln(1)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "HIPAA De-Identification Toolkit - PHI Risk Report", ln=True)
    pdf.set_text_color(*BLACK)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(2)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 185, pdf.get_y())
    pdf.ln(4)

    # Section 1: Dataset Summary
    pdf.set_text_color(*NAVY_BLUE)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Section 1 - Dataset Summary", ln=True)
    pdf.set_text_color(*BLACK)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"File Name: {file_name}", ln=True)
    pdf.cell(0, 6, f"Total Rows: {row_count}", ln=True)
    pdf.cell(0, 6, f"Total Columns: {col_count}", ln=True)
    pdf.cell(0, 6, f"PHI Columns Detected: {len(flagged)}", ln=True)
    pdf.ln(4)

    # Section 2: PHI Risk Score
    pdf.set_text_color(*NAVY_BLUE)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Section 2 - PHI Risk Score", ln=True)
    pdf.set_text_color(*BLACK)
    pdf.set_font("Helvetica", "", 10)

    def apply_grade_color(letter_grade: str):
        if letter_grade in ("A", "B"):
            pdf.set_text_color(0, 128, 0)  # green
        elif letter_grade == "C":
            pdf.set_text_color(255, 165, 0)  # orange/yellow
        else:
            pdf.set_text_color(220, 0, 0)  # red

    if mode == "Audit":
        apply_grade_color(compliance['grade'])
        pdf.cell(0, 6, f"Audit score: {compliance['score']} ({compliance['grade']})", ln=True)
        pdf.set_text_color(0, 0, 0)
    else:
        apply_grade_color(before_compliance['grade'])
        pdf.cell(0, 6, f"Before: {before_compliance['score']} ({before_compliance['grade']})", ln=True)
        pdf.set_text_color(0, 0, 0)
        if after_compliance:
            apply_grade_color(after_compliance['grade'])
            pdf.cell(0, 6, f"After: {after_compliance['score']} ({after_compliance['grade']})", ln=True)
            pdf.set_text_color(0, 0, 0)
            delta = after_compliance['score'] - before_compliance['score']
            pdf.cell(0, 6, f"Improvement: {delta:+} points", ln=True)
        else:
            pdf.cell(0, 6, "After: N/A (de-identification not run)", ln=True)
    pdf.ln(4)

    # Section 3: PHI Detection Results
    pdf.set_text_color(*NAVY_BLUE)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Section 3 - PHI Detection Results", ln=True)
    pdf.set_text_color(*BLACK)
    pdf.set_font("Helvetica", "", 10)

    if flagged:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(60, 6, "Column", border=1)
        pdf.cell(70, 6, "PHI Type(s)", border=1)
        pdf.cell(40, 6, "Confidence", border=1, ln=True)
        pdf.set_font("Helvetica", "", 10)
        for col, info in flagged.items():
            pdf.cell(60, 6, col[:30], border=1)
            pdf.cell(70, 6, ", ".join(info["phi_types"])[:30], border=1)

            confidence = info.get("confidence", "Low")
            if confidence == "High":
                pdf.set_fill_color(255, 180, 180)  # richer salmon/red
                pdf.set_text_color(180, 0, 0)      # dark red
            elif confidence == "Medium":
                pdf.set_fill_color(255, 220, 120)  # richer amber/gold
                pdf.set_text_color(160, 100, 0)    # dark orange
            else:
                pdf.set_fill_color(180, 230, 180)  # clear green
                pdf.set_text_color(0, 120, 0)      # dark green

            pdf.cell(40, 6, confidence, border=1, ln=True, fill=True)
            pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(0, 0, 0)
    else:
        pdf.cell(0, 6, "No PHI columns detected.", ln=True)

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "Clean columns:", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, ", ".join(clean.keys()) or "None")
    pdf.ln(4)

    # Section 4: Transformations / Recommendations
    pdf.set_x(pdf.l_margin)  # Reset cursor to left margin
    title = "Section 4 - Transformations Applied" if mode != "Audit" else "Section 4 - Recommendations"
    pdf.set_text_color(*NAVY_BLUE)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, title, ln=True)
    pdf.set_text_color(*BLACK)
    pdf.set_font("Helvetica", "", 10)
    if flagged:
        for col, info in flagged.items():
            pdf.set_x(pdf.l_margin)  # Reset cursor to left margin
            action = _describe_transformation(info["phi_types"], mode, col)
            pdf.multi_cell(180, 5, f"{col}: {action}")
    else:
        pdf.cell(0, 6, "No transformations required.", ln=True)
    
    pdf.ln(4)
    pdf.set_text_color(*NAVY_BLUE)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Section 5 - Disclaimer", ln=True)
    pdf.set_text_color(*BLACK)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, "This report was generated by the HIPAA De-Identification Toolkit. Detection and scoring are heuristic and may not identify every HIPAA identifier. Safe Harbor mode applies conservative transformations to PHI detected by the toolkit, but the output must be reviewed for undetected identifiers and other re-identification risk. This report is not legal advice or a substitute for professional HIPAA compliance review.")

    # Return PDF bytes
    return bytes(pdf.output())

# ---------------------------------------------------------------------------
# Streamlit App
# ---------------------------------------------------------------------------

st.title("HIPAA De-Identification Toolkit")
st.write("Upload a medical data CSV to scan for potential PHI, assess de-identification risk, and transform detected identifiers.")
st.caption("PHI detection and risk scoring are heuristic. Safe Harbor mode applies conservative rules to detected PHI and does not replace manual review or professional HIPAA compliance advice.")

logo_file = st.sidebar.file_uploader("Upload a logo for the PDF report (optional)", type=["png", "jpg", "jpeg"])
if logo_file:
    st.sidebar.image(logo_file, width=120)

uploaded_file = st.file_uploader("Upload your medical data CSV", type=["csv"])
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.subheader("Data Preview")
    st.dataframe(df.head())

    # --- PII/PHI Detection ---
    st.subheader("PHI Column Detection")
    phi_results = detect_phi_columns(df)

    flagged = {col: info for col, info in phi_results.items() if info["flagged"]}
    clean   = {col: info for col, info in phi_results.items() if not info["flagged"]}

    if flagged:
        st.error(f"{len(flagged)} column(s) contain potential PHI:")
        rows = []
        for col, info in flagged.items():
            rows.append({
                "Column":      col,
                "PHI Types":   ", ".join(info["phi_types"]),
                "Detected By": ", ".join(info["methods"]),
                "Confidence":  info["confidence"],
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.success("No PHI columns detected.")

    if clean:
        with st.expander(f"Columns with no PHI detected ({len(clean)})"):
            st.write(", ".join(clean.keys()))

    # --- PHI Risk Scoring ---
    st.subheader("PHI Risk Assessment")

    compliance = score_phi_compliance(phi_results)
    score = compliance["score"]
    grade = compliance["grade"]
    after_compliance = None

    # Choose a status color based on grade
    if grade == "A":
        grade_color = "green"
        status_msg  = "Your data appears to be in good shape. Few or no sensitive fields were detected."
        banner      = st.success
    elif grade == "B":
        grade_color = "blue"
        status_msg  = "Your data has some sensitive fields that should be reviewed before sharing."
        banner      = st.info
    elif grade == "C":
        grade_color = "orange"
        status_msg  = "Your data contains a moderate number of sensitive fields. De-identification is recommended."
        banner      = st.warning
    elif grade == "D":
        grade_color = "red"
        status_msg  = "Your data contains many sensitive fields and is not suitable for sharing without de-identification."
        banner      = st.warning
    else:  # F
        grade_color = "red"
        status_msg  = "This data contains a high number of sensitive fields and poses significant HIPAA risk. Do not share without de-identification."
        banner      = st.error

    # Prominent score + grade display
    col_score, col_grade, col_detail = st.columns([1, 1, 3])
    with col_score:
        st.metric(label="PHI Risk Score", value=f"{score} / 100")
    with col_grade:
        st.metric(label="Letter Grade", value=grade)
    with col_detail:
        st.markdown(f"**Breakdown:**")
        st.markdown(
            f"- **{compliance['high_count']}** high-risk column(s) &nbsp;→&nbsp; "
            f"−{compliance['high_count'] * 10} pts &nbsp;*(10 pts each)*"
        )
        st.markdown(
            f"- **{compliance['medium_count']}** medium-risk column(s) &nbsp;→&nbsp; "
            f"−{compliance['medium_count'] * 5} pts &nbsp;*(5 pts each)*"
        )
        st.markdown(f"- **Raw risk deductions:** {compliance['deductions']} pts *(score floors at 0)*")

    banner(status_msg)

    # --- De-Identification ---
    st.subheader("De-Identification")

    selected_mode = st.session_state.get("selected_deid_mode", "Safe Harbor De-Identification")

    if not flagged:
        st.success("No PHI columns were found — your data does not need de-identification.")
    else:
        st.write(
            f"Ready to de-identify **{len(flagged)} column(s)**. "
            "The original file will not be changed — you will download a new, cleaned copy."
        )
        
        # Show mode selector
        selected_mode = select_deid_mode(list(set([t for col_info in flagged.values() for t in col_info["phi_types"]])))

        if st.button("De-Identify My Data"):
            st.session_state["deidentified_df"] = deidentify_dataframe(df, phi_results, mode=selected_mode)
            st.session_state["selected_deid_mode"] = selected_mode
            st.success(f"✓ Data de-identified using {selected_mode} mode!")

    if "deidentified_df" in st.session_state and st.session_state["deidentified_df"] is not None:
        deidentified_df = st.session_state["deidentified_df"]

        after_compliance = compute_after_compliance(selected_mode, deidentified_df)

        st.subheader("Before vs. After PHI Risk Score")
        col_before, col_after = st.columns(2)
        with col_before:
            st.metric(
                label="Before De-Identification (Risk Score)",
                value=f"{score} / 100  ({grade})",
            )

        if after_compliance is None:
            with col_after:
                st.metric(
                    label="After De-Identification",
                    value="N/A",
                )
        else:
            with col_after:
                delta = after_compliance["score"] - score
                st.metric(
                    label=f"Verification Scan ({selected_mode})",
                    value=f"{after_compliance['score']} / 100  ({after_compliance['grade']})",
                    delta=f"+{delta} pts" if delta >= 0 else f"{delta} pts",
                )


        st.subheader("De-Identified Data Preview")
        st.dataframe(deidentified_df.head(), use_container_width=True)

        st.download_button(
            label="Download De-Identified CSV",
            data=deidentified_df.to_csv(index=False),
            file_name="de_identified_data.csv",
            mime="text/csv",
        )

    # PDF risk report generation section (works for Audit or De-ID)
    if st.button("Generate PHI Risk Report (PDF)"):
        if FPDF is None:
            st.error("Install fpdf2 to enable PDF export (pip install fpdf2).")
        else:
            try:
                report_bytes = create_compliance_report_pdf(
                    file_name=getattr(uploaded_file, "name", "uploaded_data.csv"),
                    row_count=len(df),
                    col_count=len(df.columns),
                    flagged=flagged,
                    clean=clean,
                    compliance=compliance,
                    mode=selected_mode,
                    before_compliance=compliance,
                    after_compliance=after_compliance,
                    logo_bytes=logo_file.getvalue() if logo_file else None,
                )
                st.download_button(
                    label="Download PHI Risk Report PDF",
                    data=report_bytes,
                    file_name="hipaa_phi_risk_report.pdf",
                    mime="application/pdf",
                )
            except Exception as e:
                st.error(f"Real error: {e}")