-- HIPAA De-Identification Pipeline
-- A healthcare data project demonstrating PHI and PII de-identification techniques
-- using PostgreSQL and Python. This pipeline simulates a real-world data governance
-- architecture where raw patient data is protected at the database level while a
-- de-identified analytics layer is made available to authorized roles.

-- This project implements the HIPAA Safe Harbor Method - the standard that defines
-- 18 specific identifiers that must be removed or masked to protect patient privacy.

-- This pipeline demonstrates:
-- * Masking - SSN, phone number, PCP name, first name
-- * Redaction - last name, address
-- * Generalization - date of birth reduced to birth year, admission date reduced to
-- year month, ZIP code truncated to 3 digits
-- * Tokenization - patient, record, and insurance IDs replaced with SHA-256 hashed
-- tokens
-- Role Based Access Control (RBAC) - a data_analyst role is granted access only to
-- the de-identified analytics schema, with all access to the raw_data schema
-- revoked

-- PostreSQL Setup:
-- Step 1: Create two schemas: raw_data and analytics.
CREATE SCHEMA IF NOT EXISTS raw_data;
CREATE SCHEMA IF NOT EXISTS analytics;

-- Step 2: Create the raw_data tables
CREATE TABLE raw_data.patients (
	patient_id SERIAL PRIMARY KEY,
	first_name VARCHAR(50),
	last_name VARCHAR(50),
	ssn VARCHAR(11),
	dob DATE,
	gender VARCHAR(50),
	address VARCHAR(100),
	city VARCHAR(25),
	state VARCHAR(2),
	zip VARCHAR(10),
	phone VARCHAR(25)
);

CREATE TABLE raw_data.medical_records (
	record_id SERIAL PRIMARY KEY,
	patient_id INTEGER REFERENCES raw_data.patients (patient_id),
	admissions_date DATE,
	diagnosis TEXT,
	medication VARCHAR(100),
	pcp_name VARCHAR(100)
);

CREATE TABLE raw_data.insurance (
	insurance_id SERIAL PRIMARY KEY,
	patient_id INTEGER REFERENCES raw_data.patients (patient_id),
	insurance_provider VARCHAR(100),
	member_id VARCHAR(20),
	group_number VARCHAR(20),
	policy_effective_date DATE
);

-- Step 3: Import the CSVs generated from the Python script, FakePatientData.py, into the tables.

-- Step 4: Create the Analytics Views
CREATE VIEW analytics.patients AS 
	SELECT
		ENCODE(SHA256(patient_id::text::bytea), 'hex') AS patient_token,
		LEFT(first_name,1) || '***' AS first_name,
		'REDACTED' AS last_name,
		CONCAT('XXX-XX-',RIGHT(ssn,4)) AS masked_ssn,
		EXTRACT(YEAR FROM dob) AS birth_year,
		gender,
		'REDACTED' AS address,
		LEFT(city,1) || '***' AS city,
		state,
		LEFT(zip, 3) AS zip_region,
		CONCAT('###-###-',RIGHT(phone,4)) AS masked_phone
	FROM raw_data.patients;

CREATE VIEW analytics.medical_records AS
	SELECT 
		ENCODE(SHA256(record_id::text::bytea), 'hex') AS record_token,
		ENCODE(SHA256(p.patient_id::text::bytea), 'hex') AS patient_token,
		TO_CHAR(admissions_date,'YYYY-MM') AS admissions_period,
		diagnosis,
		medication,
		LEFT(pcp_name,5) || '***' AS pcp_masked
	FROM raw_data.medical_records MR
	LEFT JOIN raw_data.patients P ON P.patient_id = MR.patient_id;

CREATE VIEW analytics.insurance AS
	SELECT 
		ENCODE(SHA256(insurance_id::text::bytea), 'hex') AS insurance_token,
		ENCODE(SHA256(p.patient_id::text::bytea), 'hex') AS patient_token,
		insurance_provider,
		CONCAT('MEM','XXXXXX') AS member_id_masked,
		CONCAT('GRP','XXXX') AS group_number_masked,
		EXTRACT(YEAR FROM policy_effective_date) AS policy_effective_year
	FROM raw_data.insurance I 
	LEFT JOIN raw_data.patients P ON P.patient_id = I.patient_id;

-- Step 5: Creating an Analyst role that can't see the raw_data schema.
-- This is called Role-Based Access Control (RBAC).
CREATE ROLE data_analyst;
GRANT USAGE ON SCHEMA analytics TO data_analyst;
GRANT SELECT ON analytics.patients, analytics.medical_records, analytics.insurance TO data_analyst;

-- Revoke all access from the raw_data schema for the analyst.
REVOKE ALL ON SCHEMA raw_data FROM data_analyst;

-- Change Role to data_analyst to verify that raw_data is not accessible
SET ROLE data_analyst;

-- SELECT query for raw_data.patients table; should throw a permissions error.
SELECT * FROM raw_data.patients;

-- RESETS Role back to original
RESET ROLE;