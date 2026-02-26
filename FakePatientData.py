"""
HIPAA De-Identification Pipeline
Fake Patient Data Generator

Generates 50 realistic but entirely fictitious patient records across
three CSV files for import into PostgreSQL.
- patients.csv: Contains patient demographics and identifiers.
- medical_records.csv: Contains medical diagnoses and treatments.
- insurance.csv: Contains insurance information for each patient.

Required Libraries:
- faker: For generating realistic fake data.
"""

import csv
from operator import index
from datetime import date, timedelta
import random
from faker import Faker

fake = Faker()

# Clinical Information

diagnoses = [
    "Hypertension",
    "Type 2 Diabetes",
    "Asthma",
    "Chronic Obstructive Pulmonary Disease (COPD)",
    "Depression",
    "Anxiety",
    "Hyperlipidemia",
    "Osteoarthritis",
    "Heart Disease",
    "Chronic Kidney Disease"
]

medications = [
    "Lisinopril",
    "Metformin",
    "Albuterol",
    "Atorvastatin",
    "Sertraline",
    "Simvastatin",
    "Levothyroxine",
    "Omeprazole",
    "Amlodipine",
    "Losartan"
]

pcp_names = [
    "Dr. John Smith",
    "Dr. Emily Johnson",
    "Dr. Michael Brown",
    "Dr. Sarah Davis",
    "Dr. David Wilson",
    "Dr. Laura Martinez",
    "Dr. James Anderson",
    "Dr. Linda Taylor",
    "Dr. Robert Thomas",
    "Dr. Karen Moore"
]

insurance_providers = [
    "HealthFirst",
    "UnitedHealthcare",
    "Blue Cross Blue Shield",
    "Aetna",
    "Cigna",
    "Humana",
    "Kaiser Permanente",
    "Centene Corporation",
    "Molina Healthcare",
    "WellCare"
]

genders = ["Male", "Female", "Non-Binary", "Prefer Not to Say"]
gender_weights = [0.48, 0.48, 0.02, 0.02]  # Approximate distribution

us_cities = [
    "Las Vegas", "Wyoming", "International Falls", "Nepaskiak", "Asheville",
    "Grants", "Lexington", "Genesee", "Euclid", "Robertsdale",
    "Weirton", "Fayetteville", "Ash Flat", "Fuquay-Varina", "El Reno",
    "Houma", "Valley City", "Georgetown", "Magnolia", "Scobey"
]

us_states = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"
]

# Helpers

def generate_patient_id(index):
    """Generates a unique patient ID."""
    return f"{index}"

def generate_admissions_date():
    """Generates a random admissions date within the last 5 years."""
    start = date(2020, 1, 1)
    end = date.today()
    delta = (end - start).days
    result = start + timedelta(days=random.randint(0, delta))
    return result.strftime("%Y-%m-%d")

def generate_policy_effective_date():
    """Generates a random policy effective date within the last 5 years."""
    start = date(2020, 1, 1)
    end = date.today()
    delta = (end - start).days
    result = start + timedelta(days=random.randint(0, delta))
    return result.strftime("%Y-%m-%d")

def generate_ssn():
    """Generates a fake Social Security Number."""
    area = random.randint(100, 899)
    group = random.randint(10, 99)
    serial = random.randint(1000, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"

def generate_zip():
    """Generates a fake ZIP code."""
    return f"{random.randint(10000, 99999):05d}"

def generate_member_id():
    """Generates a unique insurance member ID."""
    return f"MEM{random.randint(100000, 999999)}"

def generate_group_number():
    """Generates a unique insurance group number."""
    return f"GRP{random.randint(1000, 9999)}"

# Table Generators

def generate_patients(count=50):
    """Generates a list of fake patient records."""
    patients = []
    for i in range(1,51):
        patients.append({
            "patient_id": i,
            "first_name": fake.first_name(),
            "last_name": fake.last_name(),
            "ssn": generate_ssn(),
            "dob": fake.date_of_birth(minimum_age=18, maximum_age=100).strftime("%Y-%m-%d"),
            "gender": random.choices(genders, weights=gender_weights)[0],
            "address": fake.street_address(),
            "city": random.choice(us_cities),
            "state": random.choice(us_states),
            "zip": generate_zip(),
            "phone": f"({random.randint(100,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}"
        })
    return patients

def generate_medical_records(patient_ids):
    """Generates a list of fake medical records for the given patient IDs."""
    medical_records = []
    for i in range(1,51):
        num_records = random.randint(1, 5)  # Each patient can have 1-5 records
        for _ in range(num_records):
            medical_records.append({
                "patient_id":i,
                "admissions_date": generate_admissions_date(),
                "diagnosis": random.choice(diagnoses),
                "medication": random.choice(medications),
                "pcp": random.choice(pcp_names)
            })
    return medical_records

def generate_insurance(patient_ids):
    """Generates a list of fake insurance records for the given patient IDs."""
    insurance_records = []
    for i in range(1,51):
        insurance_records.append({
            "patient_id": i,
            "provider": random.choice(insurance_providers),
            "member_id": f"MEM{random.randint(100000, 999999)}",
            "group_number": f"GRP{random.randint(1000, 9999)}",
            "policy_effective_date": generate_policy_effective_date()
        })
    return insurance_records

# CSV Exporter

def export_csv(data, filename, fieldnames):
    """Exports a list of dictionaries to a CSV file."""
    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print(f"Exported {len(data)} records to {filename}")

# Main Execution

if __name__ == "__main__":
    print('\n HIPAA De-Identification Pipeline - Fake Patient Data Generator\n')
    print('-' * 50)

    patients = generate_patients()
    patient_ids = [p["patient_id"] for p in patients]
    medical_records = generate_medical_records(patient_ids)
    insurance_records = generate_insurance(patient_ids)

    print('Executing CSVs...\n')

    export_csv(
        patients,
        'patients.csv',
        ['patient_id', 'first_name', 'last_name', 'ssn', 'dob', 'gender', 'address', 'city', 'state', 'zip', 'phone']
    )
    export_csv(
        medical_records,
        'medical_records.csv',
        ['patient_id', 'admissions_date', 'diagnosis', 'medication', 'pcp']
    )
    export_csv(
        insurance_records,
        'insurance.csv',
        ['patient_id', 'provider', 'member_id', 'group_number', 'policy_effective_date']
    )

    print('\nImport into PostgreSQL using the following commands:\n')
    print(r" \copy raw_data.patients FROM 'C:\Users\jlynn\Data_Projects\hipaa_deidentification_pipeline\patients.csv' DELIMITER ',' CSV HEADER;")
    print(r" \copy raw_data.medical_records FROM 'C:\Users\jlynn\Data_Projects\hipaa_deidentification_pipeline\medical_records.csv' DELIMITER ',' CSV HEADER;")
    print(r" \copy raw_data.insurance FROM 'C:\Users\jlynn\Data_Projects\hipaa_deidentification_pipeline\insurance.csv' DELIMITER ',' CSV HEADER;")
    print()