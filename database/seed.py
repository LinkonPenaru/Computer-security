"""
database/seed.py
=================
Seed the database with:
  1. Hospital cryptographic keys (AES-256 + HMAC-SHA256)
  2. 20 simulated system users
  3. 6 system patient actors
  4. Initial consent policies for each patient

Run once: py database/seed.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db
from crypto import hashing, key_manager


# ── 20 System Users ───────────────────────────────────────────────────────────
USERS = [
    # Doctors — Hospital A
    ("DOCTOR_001", "Dr. Alice Chen",    "Doctor",     "Hospital_A"),
    ("DOCTOR_002", "Dr. Bob Kumar",     "Doctor",     "Hospital_A"),
    ("DOCTOR_003", "Dr. Grace Kim",     "Doctor",     "Hospital_A"),
    # Doctors — Hospital B
    ("DOCTOR_004", "Dr. Carol Smith",   "Doctor",     "Hospital_B"),
    ("DOCTOR_005", "Dr. David Lee",     "Doctor",     "Hospital_B"),
    ("DOCTOR_006", "Dr. Henry Patel",   "Doctor",     "Hospital_B"),
    # Doctors — Hospital C
    ("DOCTOR_007", "Dr. Eva Garcia",    "Doctor",     "Hospital_C"),
    ("DOCTOR_008", "Dr. Frank Brown",   "Doctor",     "Hospital_C"),
    ("DOCTOR_009", "Dr. Iris Wong",     "Doctor",     "Hospital_C"),
    # Nurses
    ("NURSE_001",  "Nurse Mary Johnson","Nurse",      "Hospital_A"),
    ("NURSE_002",  "Nurse James Davis", "Nurse",      "Hospital_B"),
    ("NURSE_003",  "Nurse Sarah Wilson","Nurse",      "Hospital_C"),
    # Researchers
    ("RESEARCHER_001", "Dr. Tom Martinez",  "Researcher", "Hospital_A"),
    ("RESEARCHER_002", "Dr. Linda Taylor",  "Researcher", "Hospital_B"),
    # Patient actors (they manage their own consent)
    ("PATIENT_001", "Patient Alice",    "Patient",    "Hospital_A"),
    ("PATIENT_002", "Patient Bob",      "Patient",    "Hospital_B"),
    ("PATIENT_003", "Patient Carol",    "Patient",    "Hospital_C"),
    ("PATIENT_004", "Patient David",    "Patient",    "Hospital_A"),
    ("PATIENT_005", "Patient Emma",     "Patient",    "Hospital_B"),
    ("PATIENT_006", "Patient Frank",    "Patient",    "Hospital_C"),
]

# ── System Patient Actors (used for consent management) ──────────────────────
SYSTEM_PATIENTS = [
    ("PATIENT_001", "Hospital_A"),
    ("PATIENT_002", "Hospital_B"),
    ("PATIENT_003", "Hospital_C"),
    ("PATIENT_004", "Hospital_A"),
    ("PATIENT_005", "Hospital_B"),
    ("PATIENT_006", "Hospital_C"),
]

# ── Initial Consent Policies ──────────────────────────────────────────────────
# Format: (patient_id, hospital_id, role, access_granted)
# 1 = granted, 0 = revoked
INITIAL_CONSENT = [
    # PATIENT_001 — allows A+B for Doctors; A for Nurses; denies C and Researchers
    ("PATIENT_001", "Hospital_A", "Doctor",     1),
    ("PATIENT_001", "Hospital_A", "Nurse",      1),
    ("PATIENT_001", "Hospital_B", "Doctor",     1),
    ("PATIENT_001", "Hospital_B", "Nurse",      0),
    ("PATIENT_001", "Hospital_C", "Doctor",     0),
    ("PATIENT_001", "Hospital_C", "Nurse",      0),
    ("PATIENT_001", "Hospital_A", "Researcher", 0),
    ("PATIENT_001", "Hospital_B", "Researcher", 0),
    ("PATIENT_001", "Hospital_C", "Researcher", 0),

    # PATIENT_002 — allows all hospitals for Doctors
    ("PATIENT_002", "Hospital_A", "Doctor",     1),
    ("PATIENT_002", "Hospital_B", "Doctor",     1),
    ("PATIENT_002", "Hospital_C", "Doctor",     1),
    ("PATIENT_002", "Hospital_A", "Nurse",      0),
    ("PATIENT_002", "Hospital_B", "Nurse",      1),
    ("PATIENT_002", "Hospital_C", "Nurse",      0),
    ("PATIENT_002", "Hospital_A", "Researcher", 1),
    ("PATIENT_002", "Hospital_B", "Researcher", 0),
    ("PATIENT_002", "Hospital_C", "Researcher", 0),

    # PATIENT_003
    ("PATIENT_003", "Hospital_A", "Doctor",     1),
    ("PATIENT_003", "Hospital_B", "Doctor",     1),
    ("PATIENT_003", "Hospital_C", "Doctor",     1),
    ("PATIENT_003", "Hospital_A", "Nurse",      1),
    ("PATIENT_003", "Hospital_B", "Nurse",      1),
    ("PATIENT_003", "Hospital_C", "Nurse",      1),
    ("PATIENT_003", "Hospital_A", "Researcher", 0),
    ("PATIENT_003", "Hospital_B", "Researcher", 0),
    ("PATIENT_003", "Hospital_C", "Researcher", 0),

    # PATIENT_004
    ("PATIENT_004", "Hospital_A", "Doctor",     1),
    ("PATIENT_004", "Hospital_B", "Doctor",     0),
    ("PATIENT_004", "Hospital_C", "Doctor",     0),
    ("PATIENT_004", "Hospital_A", "Nurse",      1),
    ("PATIENT_004", "Hospital_B", "Nurse",      0),
    ("PATIENT_004", "Hospital_C", "Nurse",      0),
    ("PATIENT_004", "Hospital_A", "Researcher", 1),
    ("PATIENT_004", "Hospital_B", "Researcher", 0),
    ("PATIENT_004", "Hospital_C", "Researcher", 0),

    # PATIENT_005
    ("PATIENT_005", "Hospital_A", "Doctor",     0),
    ("PATIENT_005", "Hospital_B", "Doctor",     1),
    ("PATIENT_005", "Hospital_C", "Doctor",     1),
    ("PATIENT_005", "Hospital_A", "Nurse",      0),
    ("PATIENT_005", "Hospital_B", "Nurse",      1),
    ("PATIENT_005", "Hospital_C", "Nurse",      0),
    ("PATIENT_005", "Hospital_A", "Researcher", 0),
    ("PATIENT_005", "Hospital_B", "Researcher", 1),
    ("PATIENT_005", "Hospital_C", "Researcher", 0),

    # PATIENT_006
    ("PATIENT_006", "Hospital_A", "Doctor",     1),
    ("PATIENT_006", "Hospital_B", "Doctor",     1),
    ("PATIENT_006", "Hospital_C", "Doctor",     1),
    ("PATIENT_006", "Hospital_A", "Nurse",      0),
    ("PATIENT_006", "Hospital_B", "Nurse",      0),
    ("PATIENT_006", "Hospital_C", "Nurse",      1),
    ("PATIENT_006", "Hospital_A", "Researcher", 0),
    ("PATIENT_006", "Hospital_B", "Researcher", 0),
    ("PATIENT_006", "Hospital_C", "Researcher", 1),
]


def seed():
    """Run all seeding steps."""
    db.init_db()

    # 1. Hospital keys
    existing_keys = db.fetchone("SELECT COUNT(*) as c FROM hospital_keys")
    if existing_keys and existing_keys["c"] > 0:
        print("Hospital keys already exist — loading from database.")
        stored = {r["hospital_id"]: {
            "ehr_key":    r["ehr_key_b64"],
            "search_key": r["search_key_b64"],
        } for r in db.fetchall("SELECT * FROM hospital_keys")}
        key_manager.initialize_keys(stored)
    else:
        print("Generating hospital cryptographic keys …")
        keys = key_manager.initialize_keys()
        for hosp, kdata in keys.items():
            db.execute(
                "INSERT OR IGNORE INTO hospital_keys (hospital_id, ehr_key_b64, search_key_b64) VALUES (?,?,?)",
                (hosp, kdata["ehr_key"], kdata["search_key"]),
            )
        print(f"  Keys stored for: {list(keys.keys())}")

    # 2. Users
    user_count = db.fetchone("SELECT COUNT(*) as c FROM users")["c"]
    if user_count == 0:
        print(f"Inserting {len(USERS)} system users …")
        for user_id, full_name, role, hospital_id in USERS:
            user_hash = hashing.hash_user_id(user_id)
            db.execute(
                """INSERT OR IGNORE INTO users
                       (user_id, user_hash, full_name, role, hospital_id, status)
                   VALUES (?,?,?,?,?,'ACTIVE')""",
                (user_id, user_hash, full_name, role, hospital_id),
            )
    else:
        print(f"Users already seeded ({user_count} found).")

    # 3. System patients
    pat_count = db.fetchone("SELECT COUNT(*) as c FROM system_patients")["c"]
    if pat_count == 0:
        print(f"Inserting {len(SYSTEM_PATIENTS)} patient actors …")
        for patient_id, hospital in SYSTEM_PATIENTS:
            patient_hash = hashing.hash_user_id(patient_id)
            db.execute(
                "INSERT OR IGNORE INTO system_patients (patient_id, patient_hash, assigned_hospital) VALUES (?,?,?)",
                (patient_id, patient_hash, hospital),
            )
    else:
        print(f"Patient actors already seeded ({pat_count} found).")

    # 4. Consent policies
    con_count = db.fetchone("SELECT COUNT(*) as c FROM consent_policies")["c"]
    if con_count == 0:
        print(f"Inserting {len(INITIAL_CONSENT)} consent policies …")
        for patient_id, hospital_id, role, granted in INITIAL_CONSENT:
            patient_hash = hashing.hash_user_id(patient_id)
            status = "ACTIVE" if granted else "REVOKED"
            db.execute(
                """INSERT OR IGNORE INTO consent_policies
                       (patient_hash, hospital_id, role, access_granted, status)
                   VALUES (?,?,?,?,?)""",
                (patient_hash, hospital_id, role, granted, status),
            )
    else:
        print(f"Consent policies already seeded ({con_count} found).")

    # Summary
    print("\n=== Seed Complete ===")
    print(f"  Users    : {db.fetchone('SELECT COUNT(*) c FROM users')['c']}")
    print(f"  Patients : {db.fetchone('SELECT COUNT(*) c FROM system_patients')['c']}")
    print(f"  Consents : {db.fetchone('SELECT COUNT(*) c FROM consent_policies')['c']}")
    print(f"  Keys     : {db.fetchone('SELECT COUNT(*) c FROM hospital_keys')['c']} hospitals")


if __name__ == "__main__":
    seed()
    print("\nDatabase ready. Now run: py data/preprocess_mimic.py")
