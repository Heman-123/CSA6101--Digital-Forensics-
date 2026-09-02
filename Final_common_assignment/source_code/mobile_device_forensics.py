"""
CSA6101 - Digital Forensics and Cybercrime Investigation
Assignment:
Mobile Device Forensics: Smartphone Data Breach Evidence Management
and Incident Reconstruction System using Python

Standard-library implementation.
Data is stored locally in forensic_case_data.json.
Use only authorized/simulated forensic evidence for academic work.
"""

import csv
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path

DB_FILE = Path("forensic_case_data.json")
REPORT_DIR = Path("forensic_reports")
EVIDENCE_DIR = Path("evidence_files")

ARTIFACT_TYPES = [
    "Call Records",
    "SMS/Chat Export",
    "Application Usage/Auth Logs",
    "GPS Location History",
    "Network Traffic Capture",
    "Other",
]

SUSPICIOUS_KEYWORDS = [
    "unauthorized",
    "failed login",
    "unknown login",
    "suspicious",
    "new app",
    "installed",
    "exfiltration",
    "data upload",
    "large upload",
    "malware",
    "unknown ip",
    "impossible travel",
]


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def safe_input(prompt, required=True):
    while True:
        value = input(prompt).strip()
        if value or not required:
            return value
        print("This field is mandatory.")


def parse_datetime(value):
    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.max.replace(tzinfo=None)


def sha256_file(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_db():
    if not DB_FILE.exists():
        return {
            "case": {
                "case_id": "CASE-001",
                "title": "Regional Bank Smartphone Data Breach",
                "background": (
                    "Suspected compromise of an employee smartphone. "
                    "The system is used to preserve, cross-check and correlate "
                    "simulated handset-derived evidence."
                ),
                "created_at": now(),
            },
            "devices": [],
            "artifacts": [],
            "custody": [],
            "baseline": [],
            "snapshots": [],
            "events": [],
        }

    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        print("Database file could not be read. Starting a new case database.")
        return {
            "case": {
                "case_id": "CASE-001",
                "title": "Regional Bank Smartphone Data Breach",
                "background": "",
                "created_at": now(),
            },
            "devices": [],
            "artifacts": [],
            "custody": [],
            "baseline": [],
            "snapshots": [],
            "events": [],
        }


def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


def next_id(prefix, records, key):
    nums = []
    for item in records:
        value = str(item.get(key, ""))
        m = re.search(r"(\d+)$", value)
        if m:
            nums.append(int(m.group(1)))
    return f"{prefix}-{max(nums, default=0) + 1:04d}"


def choose_from(items, title):
    if not items:
        print(f"No {title.lower()} available.")
        return None

    print(f"\n{title}")
    for i, item in enumerate(items, 1):
        print(f"{i}. {item}")

    while True:
        raw = input("Select number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return items[int(raw) - 1]
        print("Invalid selection.")


def create_sample_files():
    """
    Creates harmless simulated evidence files so the SHA-256 workflow can
    be demonstrated without using real personal/device data.
    """
    EVIDENCE_DIR.mkdir(exist_ok=True)

    samples = {
        "calls_sample.csv": (
            "timestamp,caller,callee,direction\n"
            "2026-08-28T09:10:00+05:30,1001,2001,outgoing\n"
            "2026-08-28T09:25:00+05:30,2001,1001,incoming\n"
        ),
        "messages_sample.csv": (
            "timestamp,sender,receiver,message\n"
            "2026-08-28T09:30:00+05:30,employee,bank-support,Login alert received\n"
            "2026-08-28T09:55:00+05:30,employee,manager,Please verify unusual activity\n"
        ),
        "app_auth_sample.csv": (
            "timestamp,event,application,details\n"
            "2026-08-28T09:42:00+05:30,unauthorized login,BankPortal,unknown IP 203.0.113.50\n"
            "2026-08-28T09:46:00+05:30,new app,UnknownTransfer,installed from unknown source\n"
        ),
        "gps_sample.csv": (
            "timestamp,latitude,longitude,event\n"
            "2026-08-28T09:40:00+05:30,13.0827,80.2707,normal location\n"
            "2026-08-28T09:50:00+05:30,12.9716,77.5946,unexpected location\n"
        ),
        "network_sample.csv": (
            "timestamp,src_ip,dst_ip,bytes,event\n"
            "2026-08-28T09:47:00+05:30,10.0.0.15,203.0.113.50,25000,connection\n"
            "2026-08-28T09:49:00+05:30,10.0.0.15,203.0.113.50,85000000,large upload / exfiltration\n"
        ),
        "installed_apps_baseline.csv": (
            "name,version\n"
            "BankPortal,5.2\n"
            "Messages,12.1\n"
            "Maps,10.4\n"
            "Camera,8.0\n"
        ),
        "installed_apps_later.csv": (
            "name,version\n"
            "BankPortal,5.2\n"
            "Messages,12.1\n"
            "Maps,10.5\n"
            "Camera,8.0\n"
            "UnknownTransfer,1.0\n"
        ),
    }

    for name, content in samples.items():
        path = EVIDENCE_DIR / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")

    print(f"Sample evidence created in: {EVIDENCE_DIR.resolve()}")


def enroll_device(db):
    print("\n--- DEVICE ENROLLMENT ---")
    device_id = next_id("DEV", db["devices"], "device_id")
    source = safe_input("Smartphone model / IMEI / extraction identifier: ")
    origin = safe_input("Evidence origin/source: ")
    acquisition = safe_input(f"Acquisition date/time [{now()}]: ", required=False) or now()
    examiner = safe_input("Examiner name/details: ")
    storage = safe_input("Evidence storage location: ")

    device = {
        "device_id": device_id,
        "source": source,
        "origin": origin,
        "acquisition_datetime": acquisition,
        "examiner": examiner,
        "storage_location": storage,
        "enrolled_at": now(),
    }

    db["devices"].append(device)
    save_db(db)
    print(f"Device enrolled successfully. Device ID: {device_id}")


def enroll_artifact(db):
    print("\n--- ARTIFACT ENROLLMENT ---")
    if not db["devices"]:
        print("Enroll a device first.")
        return

    device = choose_from(
        db["devices"],
        "Select Device",
    )
    if not device:
        return

    evidence_id = next_id("EVD", db["artifacts"], "evidence_id")
    print("Artifact types:")
    for i, t in enumerate(ARTIFACT_TYPES, 1):
        print(f"{i}. {t}")

    while True:
        raw = input("Select artifact type: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(ARTIFACT_TYPES):
            artifact_type = ARTIFACT_TYPES[int(raw) - 1]
            break
        print("Invalid selection.")

    file_path = safe_input("Path to extracted artifact file: ")
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        print("File does not exist or is not a regular file.")
        return

    try:
        checksum = sha256_file(path)
    except OSError as e:
        print(f"Could not hash file: {e}")
        return

    acquisition = safe_input(f"Acquisition date/time [{now()}]: ", required=False) or now()
    examiner = safe_input("Examiner details: ")
    storage = safe_input("Storage location: ")

    artifact = {
        "evidence_id": evidence_id,
        "device_id": device["device_id"],
        "artifact_type": artifact_type,
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "acquisition_datetime": acquisition,
        "examiner": examiner,
        "storage_location": storage,
        "intake_sha256": checksum,
        "enrolled_at": now(),
    }

    db["artifacts"].append(artifact)
    save_db(db)

    print("\nArtifact enrolled.")
    print(f"Evidence ID : {evidence_id}")
    print(f"SHA-256     : {checksum}")


def record_custody(db):
    print("\n--- CHAIN OF CUSTODY ---")
    items = db["devices"] + db["artifacts"]
    if not items:
        print("No device or artifact enrolled.")
        return

    labels = []
    mapping = {}
    for d in db["devices"]:
        label = f"DEVICE {d['device_id']} - {d['source']}"
        labels.append(label)
        mapping[label] = ("device", d["device_id"])
    for a in db["artifacts"]:
        label = f"ARTIFACT {a['evidence_id']} - {a['artifact_type']} - {a['file_name']}"
        labels.append(label)
        mapping[label] = ("artifact", a["evidence_id"])

    selected = choose_from(labels, "Select Item")
    if not selected:
        return

    item_type, item_id = mapping[selected]
    handler = safe_input("Handler / examiner name: ")
    reason = safe_input("Reason for handover: ")
    timestamp = safe_input(f"Timestamp [{now()}]: ", required=False) or now()

    entry_id = next_id("CUS", db["custody"], "custody_id")
    entry = {
        "custody_id": entry_id,
        "item_type": item_type,
        "item_id": item_id,
        "handler": handler,
        "timestamp": timestamp,
        "reason": reason,
    }

    db["custody"].append(entry)
    save_db(db)
    print(f"Custody entry recorded: {entry_id}")


def display_custody(db):
    print("\n--- DISPLAY CUSTODY HISTORY ---")
    if not db["custody"]:
        print("No custody entries.")
        return

    item_ids = sorted(set(str(x["item_id"]) for x in db["custody"]))
    selected_id = choose_from(item_ids, "Evidence/Device IDs with custody entries")
    if not selected_id:
        return

    records = [
        x for x in db["custody"]
        if str(x["item_id"]) == str(selected_id)
    ]
    records.sort(key=lambda x: parse_datetime(x["timestamp"]))

    print(f"\nCustody history for {selected_id}")
    print("-" * 80)
    for r in records:
        print(
            f"{r['custody_id']} | {r['timestamp']} | "
            f"{r['handler']} | {r['reason']}"
        )


def verify_checksum(db):
    print("\n--- SHA-256 CHECKSUM CONFIRMATION ---")
    if not db["artifacts"]:
        print("No artifacts enrolled.")
        return

    labels = [
        f"{a['evidence_id']} - {a['artifact_type']} - {a['file_name']}"
        for a in db["artifacts"]
    ]
    selected = choose_from(labels, "Select Artifact")
    if not selected:
        return

    evidence_id = selected.split(" - ", 1)[0]
    artifact = next(a for a in db["artifacts"] if a["evidence_id"] == evidence_id)
    path = Path(artifact["file_path"])

    if not path.exists():
        print("RESULT: FAIL - evidence file is missing.")
        return

    try:
        current = sha256_file(path)
    except OSError as e:
        print(f"Hashing failed: {e}")
        return

    stored = artifact["intake_sha256"]
    print(f"Stored SHA-256 : {stored}")
    print(f"Current SHA-256: {current}")

    if stored.lower() == current.lower():
        result = "PASS - checksum matches; no integrity discrepancy detected."
    else:
        result = "FAIL - checksum mismatch; potential alteration/tampering."
    print("RESULT:", result)

    artifact.setdefault("reviews", []).append({
        "reviewed_at": now(),
        "stored_sha256": stored,
        "fresh_sha256": current,
        "result": result,
    })
    save_db(db)


def read_csv_rows(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def create_snapshot(db):
    print("\n--- BASELINE / LATER SNAPSHOT ---")
    file_path = safe_input("Path to installed-app CSV snapshot: ")
    path = Path(file_path)

    if not path.exists():
        print("Snapshot file not found.")
        return

    try:
        rows = read_csv_rows(path)
    except Exception as e:
        print(f"Could not read CSV: {e}")
        return

    required = {"name", "version"}
    if not rows or not required.issubset(rows[0].keys()):
        print("CSV must contain columns: name, version")
        return

    snapshot_type = safe_input("Snapshot type (baseline/later): ").lower()
    if snapshot_type not in {"baseline", "later"}:
        print("Enter baseline or later.")
        return

    snapshot_id = next_id("SNP", db["snapshots"], "snapshot_id")
    snapshot = {
        "snapshot_id": snapshot_id,
        "type": snapshot_type,
        "source_file": str(path.resolve()),
        "captured_at": now(),
        "apps": rows,
    }
    db["snapshots"].append(snapshot)

    if snapshot_type == "baseline":
        db["baseline"] = rows

    save_db(db)
    print(f"{snapshot_type.title()} snapshot stored: {snapshot_id}")


def cross_check_snapshots(db):
    print("\n--- HANDSET ARTIFACT CROSS-CHECK ---")
    baseline = db.get("baseline", [])
    later_candidates = [s for s in db["snapshots"] if s["type"] == "later"]

    if not baseline:
        print("No baseline snapshot found.")
        return
    if not later_candidates:
        print("No later snapshot found.")
        return

    later = later_candidates[-1]["apps"]

    base = {r["name"]: r.get("version", "") for r in baseline}
    current = {r["name"]: r.get("version", "") for r in later}

    missing = sorted(set(base) - set(current))
    newly_introduced = sorted(set(current) - set(base))
    altered = sorted(
        name for name in set(base) & set(current)
        if base[name] != current[name]
    )

    print("\nCROSS-CHECK RESULTS")
    print("Missing apps    :", ", ".join(missing) if missing else "None")
    print("Newly introduced:", ", ".join(newly_introduced) if newly_introduced else "None")
    print("Altered versions:", ", ".join(
        f"{x} ({base[x]} -> {current[x]})" for x in altered
    ) if altered else "None")

    if missing or newly_introduced or altered:
        print("STATUS: DISCREPANCIES DETECTED")
    else:
        print("STATUS: No differences detected")


def import_events_from_csv(db, source_name, file_path):
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {path}")
        return 0

    try:
        rows = read_csv_rows(path)
    except Exception as e:
        print(f"Could not read {path}: {e}")
        return 0

    count = 0
    for row in rows:
        timestamp = row.get("timestamp", "").strip()
        if not timestamp:
            continue

        details = " | ".join(
            f"{k}={v}" for k, v in row.items()
            if k != "timestamp" and v not in (None, "")
        )

        event_type = row.get("event") or row.get("type") or row.get("action") or source_name

        db["events"].append({
            "event_id": next_id("EVT", db["events"], "event_id"),
            "source": source_name,
            "timestamp": timestamp,
            "event_type": event_type,
            "details": details,
        })
        count += 1

    return count


def assemble_sequence(db):
    print("\n--- CROSS-SOURCE SEQUENCE ASSEMBLY ---")
    print("This routine uses at least three handset-derived sources.")

    files = []
    source_names = [
        ("Application Usage / Authentication Logs", "app_auth_sample.csv"),
        ("SMS / Messaging Records", "messages_sample.csv"),
        ("GPS Location History", "gps_sample.csv"),
        ("Network Traffic Events", "network_sample.csv"),
        ("Call Records", "calls_sample.csv"),
    ]

    print("\nAvailable default simulated sources:")
    for i, (name, filename) in enumerate(source_names, 1):
        print(f"{i}. {name} -> {EVIDENCE_DIR / filename}")

    raw = input("Enter source numbers (e.g. 1,2,3,4): ").strip()
    try:
        indexes = [int(x.strip()) for x in raw.split(",") if x.strip()]
        selected = [source_names[i - 1] for i in indexes]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    if len(selected) < 3:
        print("Select at least three sources.")
        return

    added = 0
    for source_name, filename in selected:
        path = EVIDENCE_DIR / filename
        added += import_events_from_csv(db, source_name, path)

    save_db(db)

    events = sorted(
        db["events"],
        key=lambda e: parse_datetime(e["timestamp"])
    )

    print(f"\nImported {added} events.")
    print("\nNORMALIZED CHRONOLOGICAL SEQUENCE")
    print("=" * 115)
    print(f"{'Time':25} | {'Source':35} | {'Event':25} | Details")
    print("-" * 115)
    for e in events:
        print(
            f"{e['timestamp'][:25]:25} | "
            f"{e['source'][:35]:35} | "
            f"{e['event_type'][:25]:25} | "
            f"{e['details']}"
        )


def interpret_breach(db):
    print("\n--- ARTIFACT INTERPRETATION & COMPROMISE DETECTION ---")
    if not db["events"]:
        print("No assembled events. Run sequence assembly first.")
        return

    events = sorted(db["events"], key=lambda e: parse_datetime(e["timestamp"]))

    suspicious = []
    for e in events:
        text = (
            f"{e['event_type']} {e['details']}"
        ).lower()
        score = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in text)

        # Stronger weight for common compromise indicators.
        if "unauthorized login" in text:
            score += 5
        if "exfiltration" in text or "large upload" in text:
            score += 5
        if "new app" in text or "installed from unknown source" in text:
            score += 4

        if score > 0:
            suspicious.append((score, e))

    if not suspicious:
        print("No suspicious indicators were detected by the configured rules.")
        return

    suspicious.sort(key=lambda x: (parse_datetime(x[1]["timestamp"]), -x[0]))
    earliest = suspicious[0][1]

    print("\nEARLIEST PLAUSIBLE COMPROMISE POINT")
    print("-----------------------------------")
    print(f"Event ID : {earliest['event_id']}")
    print(f"Time     : {earliest['timestamp']}")
    print(f"Source   : {earliest['source']}")
    print(f"Event    : {earliest['event_type']}")
    print(f"Details  : {earliest['details']}")

    earliest_dt = parse_datetime(earliest["timestamp"])
    follow_on = [
        e for e in events
        if parse_datetime(e["timestamp"]) >= earliest_dt
        and e["event_id"] != earliest["event_id"]
        and (
            any(k in f"{e['event_type']} {e['details']}".lower()
                for k in SUSPICIOUS_KEYWORDS)
        )
    ]

    print("\nFOLLOW-ON ACTIVITY")
    print("------------------")
    if follow_on:
        for e in follow_on:
            print(
                f"- {e['timestamp']} | {e['source']} | "
                f"{e['event_type']} | {e['details']}"
            )
    else:
        print("No rule-matched follow-on activity.")

    print("\nEXAMINER INTERPRETATION")
    print("-----------------------")
    print(
        "The earliest suspicious event is treated as a plausible compromise "
        "point, not as proof by itself. The conclusion should be supported "
        "by correlated records from independent handset-derived sources."
    )


def missing_mandatory_fields(db):
    issues = []

    device_required = [
        "device_id", "source", "origin",
        "acquisition_datetime", "examiner", "storage_location"
    ]
    artifact_required = [
        "evidence_id", "device_id", "artifact_type", "file_name",
        "file_path", "acquisition_datetime", "examiner",
        "storage_location", "intake_sha256"
    ]
    custody_required = [
        "custody_id", "item_type", "item_id", "handler",
        "timestamp", "reason"
    ]

    for d in db["devices"]:
        missing = [x for x in device_required if not d.get(x)]
        if missing:
            issues.append(f"Device {d.get('device_id', 'UNKNOWN')}: {', '.join(missing)}")

    for a in db["artifacts"]:
        missing = [x for x in artifact_required if not a.get(x)]
        if missing:
            issues.append(f"Artifact {a.get('evidence_id', 'UNKNOWN')}: {', '.join(missing)}")

    for c in db["custody"]:
        missing = [x for x in custody_required if not c.get(x)]
        if missing:
            issues.append(f"Custody {c.get('custody_id', 'UNKNOWN')}: {', '.join(missing)}")

    return issues


def generate_report(db):
    print("\n--- FORENSIC WRITE-UP GENERATION ---")
    REPORT_DIR.mkdir(exist_ok=True)

    issues = missing_mandatory_fields(db)
    events = sorted(db["events"], key=lambda e: parse_datetime(e["timestamp"]))

    suspicious = []
    for e in events:
        text = f"{e['event_type']} {e['details']}".lower()
        score = sum(1 for k in SUSPICIOUS_KEYWORDS if k in text)
        if "unauthorized login" in text:
            score += 5
        if "exfiltration" in text or "large upload" in text:
            score += 5
        if "new app" in text:
            score += 4
        if score > 0:
            suspicious.append((parse_datetime(e["timestamp"]), e, score))

    earliest = min(suspicious, key=lambda x: x[0])[1] if suspicious else None

    lines = []
    lines.append("DIGITAL FORENSIC EXAMINATION REPORT")
    lines.append("=" * 80)
    lines.append(f"Case ID: {db['case']['case_id']}")
    lines.append(f"Case Title: {db['case']['title']}")
    lines.append(f"Report Generated: {now()}")
    lines.append("")
    lines.append("1. CASE BACKGROUND")
    lines.append("-" * 80)
    lines.append(db["case"].get("background", ""))
    lines.append("")
    lines.append("2. ITEMS EXAMINED")
    lines.append("-" * 80)

    if db["devices"]:
        for d in db["devices"]:
            lines.append(
                f"Device {d['device_id']}: {d['source']} | Origin: {d['origin']} | "
                f"Acquired: {d['acquisition_datetime']} | Examiner: {d['examiner']} | "
                f"Storage: {d['storage_location']}"
            )
    else:
        lines.append("No devices enrolled.")

    for a in db["artifacts"]:
        lines.append(
            f"Artifact {a['evidence_id']}: {a['artifact_type']} | "
            f"File: {a['file_name']} | SHA-256: {a['intake_sha256']}"
        )

    lines.append("")
    lines.append("3. CHAIN OF CUSTODY")
    lines.append("-" * 80)
    if db["custody"]:
        for c in sorted(db["custody"], key=lambda x: parse_datetime(x["timestamp"])):
            lines.append(
                f"{c['custody_id']} | {c['item_type']} {c['item_id']} | "
                f"{c['timestamp']} | Handler: {c['handler']} | Reason: {c['reason']}"
            )
    else:
        lines.append("No custody-transfer records entered.")

    lines.append("")
    lines.append("4. INTEGRITY / CHECKSUM REVIEW")
    lines.append("-" * 80)
    for a in db["artifacts"]:
        reviews = a.get("reviews", [])
        if not reviews:
            lines.append(f"{a['evidence_id']}: No later checksum review recorded.")
        else:
            last = reviews[-1]
            lines.append(
                f"{a['evidence_id']}: {last['result']} | "
                f"Stored={last['stored_sha256']} | Fresh={last['fresh_sha256']}"
            )

    lines.append("")
    lines.append("5. CROSS-CHECK REVIEW")
    lines.append("-" * 80)
    if db.get("baseline") and [s for s in db["snapshots"] if s["type"] == "later"]:
        base = {r["name"]: r.get("version", "") for r in db["baseline"]}
        later = [s for s in db["snapshots"] if s["type"] == "later"][-1]["apps"]
        cur = {r["name"]: r.get("version", "") for r in later}
        lines.append(f"Missing apps: {sorted(set(base) - set(cur)) or 'None'}")
        lines.append(f"New apps: {sorted(set(cur) - set(base)) or 'None'}")
        altered = [
            n for n in set(base) & set(cur) if base[n] != cur[n]
        ]
        lines.append(
            "Altered versions: " +
            (str([(n, base[n], cur[n]) for n in altered]) if altered else "None")
        )
    else:
        lines.append("Baseline/later snapshots are incomplete.")

    lines.append("")
    lines.append("6. NORMALIZED EVENT SEQUENCE")
    lines.append("-" * 80)
    if events:
        for e in events:
            lines.append(
                f"{e['timestamp']} | {e['source']} | "
                f"{e['event_type']} | {e['details']}"
            )
    else:
        lines.append("No event sequence assembled.")

    lines.append("")
    lines.append("7. COMPROMISE-POINT ANALYSIS")
    lines.append("-" * 80)
    if earliest:
        lines.append("FACTUAL FINDING:")
        lines.append(
            f"The earliest rule-matched suspicious event was {earliest['event_id']} "
            f"at {earliest['timestamp']} from {earliest['source']}: "
            f"{earliest['event_type']} - {earliest['details']}"
        )
        lines.append("")
        lines.append("EXAMINER INTERPRETATION:")
        lines.append(
            "This event is considered a plausible compromise point because it "
            "precedes other suspicious activity in the normalized sequence. "
            "This is an analytical interpretation and should be corroborated "
            "by the underlying evidence and independent sources."
        )
    else:
        lines.append("No suspicious compromise point was identified by the configured rules.")

    lines.append("")
    lines.append("8. MANDATORY-FIELD VALIDATION")
    lines.append("-" * 80)
    if issues:
        lines.append("REPORT FINALIZATION WARNING - MISSING DETAILS:")
        lines.extend(f"- {x}" for x in issues)
    else:
        lines.append("All configured mandatory device, artifact and custody fields are present.")

    lines.append("")
    lines.append("9. CONCLUSION")
    lines.append("-" * 80)
    if earliest:
        lines.append(
            "The simulated handset evidence was enrolled, integrity-checked, "
            "cross-checked, temporally correlated and interpreted. The earliest "
            "suspicious event is reported as a plausible compromise point, "
            "with factual evidence separated from examiner interpretation."
        )
    else:
        lines.append(
            "The case data was processed, but no compromise point was identified "
            "by the configured detection rules."
        )

    lines.append("")
    lines.append("10. EVIDENCE-HANDLING NOTE")
    lines.append("-" * 80)
    lines.append(
        "This academic prototype is designed for authorized/simulated forensic "
        "evidence only. Real call, SMS/chat, GPS and network data should be "
        "handled under applicable law, organizational policy, privacy controls "
        "and documented forensic procedures."
    )

    report_text = "\n".join(lines)
    report_path = REPORT_DIR / f"{db['case']['case_id']}_forensic_report.txt"
    report_path.write_text(report_text, encoding="utf-8")

    print(f"\nReport generated: {report_path.resolve()}")
    if issues:
        print("\nWARNING: report contains missing mandatory-field flags.")
    else:
        print("Mandatory-field validation: PASS")


def seed_demo_case(db):
    """
    One-click demonstration using the supplied simulated sample files.
    It does not overwrite existing records.
    """
    print("\n--- LOAD DEMONSTRATION CASE ---")
    create_sample_files()

    if not db["devices"]:
        db["devices"].append({
            "device_id": "DEV-0001",
            "source": "Simulated Employee Smartphone / Extraction DEMO-001",
            "origin": "Regional Bank IT Security Team - simulated seizure",
            "acquisition_datetime": "2026-08-28T09:00:00+05:30",
            "examiner": "Demo Examiner",
            "storage_location": "Forensic Evidence Locker A-01",
            "enrolled_at": now(),
        })

    # Enroll sample artifacts and calculate real SHA-256 hashes.
    existing_names = {a["file_name"] for a in db["artifacts"]}
    for filename, artifact_type in [
        ("calls_sample.csv", "Call Records"),
        ("messages_sample.csv", "SMS/Chat Export"),
        ("app_auth_sample.csv", "Application Usage/Auth Logs"),
        ("gps_sample.csv", "GPS Location History"),
        ("network_sample.csv", "Network Traffic Capture"),
    ]:
        path = EVIDENCE_DIR / filename
        if filename not in existing_names:
            db["artifacts"].append({
                "evidence_id": next_id("EVD", db["artifacts"], "evidence_id"),
                "device_id": "DEV-0001",
                "artifact_type": artifact_type,
                "file_name": filename,
                "file_path": str(path.resolve()),
                "acquisition_datetime": "2026-08-28T09:00:00+05:30",
                "examiner": "Demo Examiner",
                "storage_location": "Forensic Evidence Locker A-01",
                "intake_sha256": sha256_file(path),
                "enrolled_at": now(),
            })

    if not db["custody"]:
        db["custody"] = [
            {
                "custody_id": "CUS-0001",
                "item_type": "device",
                "item_id": "DEV-0001",
                "handler": "First Responder",
                "timestamp": "2026-08-28T09:05:00+05:30",
                "reason": "Seizure and transfer to forensic examiner",
            },
            {
                "custody_id": "CUS-0002",
                "item_type": "device",
                "item_id": "DEV-0001",
                "handler": "Demo Examiner",
                "timestamp": "2026-08-28T09:20:00+05:30",
                "reason": "Forensic acquisition and examination",
            },
        ]

    if not db["baseline"]:
        rows = read_csv_rows(EVIDENCE_DIR / "installed_apps_baseline.csv")
        db["baseline"] = rows
        db["snapshots"].append({
            "snapshot_id": "SNP-0001",
            "type": "baseline",
            "source_file": str((EVIDENCE_DIR / "installed_apps_baseline.csv").resolve()),
            "captured_at": "2026-08-28T09:00:00+05:30",
            "apps": rows,
        })

    if not any(s["type"] == "later" for s in db["snapshots"]):
        rows = read_csv_rows(EVIDENCE_DIR / "installed_apps_later.csv")
        db["snapshots"].append({
            "snapshot_id": "SNP-0002",
            "type": "later",
            "source_file": str((EVIDENCE_DIR / "installed_apps_later.csv").resolve()),
            "captured_at": "2026-08-28T10:00:00+05:30",
            "apps": rows,
        })

    # Avoid repeatedly importing the same demo event IDs by checking source/time.
    if not db["events"]:
        for source_name, filename in [
            ("Application Usage / Authentication Logs", "app_auth_sample.csv"),
            ("SMS / Messaging Records", "messages_sample.csv"),
            ("GPS Location History", "gps_sample.csv"),
            ("Network Traffic Events", "network_sample.csv"),
        ]:
            import_events_from_csv(db, source_name, EVIDENCE_DIR / filename)

    save_db(db)
    print("Demonstration case loaded.")
    print("You can now run checksum, cross-check, sequence, interpretation and report functions.")


def show_case_summary(db):
    print("\n--- CASE SUMMARY ---")
    print("Case ID :", db["case"]["case_id"])
    print("Title   :", db["case"]["title"])
    print("Devices :", len(db["devices"]))
    print("Artifacts:", len(db["artifacts"]))
    print("Custody :", len(db["custody"]))
    print("Snapshots:", len(db["snapshots"]))
    print("Events  :", len(db["events"]))


def main():
    db = load_db()

    while True:
        print("\n" + "=" * 70)
        print(" MOBILE DEVICE FORENSICS EVIDENCE MANAGEMENT SYSTEM")
        print(" CSA6101 - Digital Forensics and Cybercrime Investigation")
        print("=" * 70)
        print("1.  Enroll seized smartphone")
        print("2.  Enroll extracted artifact + SHA-256 intake hash")
        print("3.  Record custody handover")
        print("4.  Display custody history")
        print("5.  Verify artifact SHA-256 checksum")
        print("6.  Store baseline/later app snapshot")
        print("7.  Cross-check baseline vs later snapshot")
        print("8.  Assemble cross-source event sequence")
        print("9.  Detect plausible compromise point")
        print("10. Generate forensic write-up")
        print("11. Load simulated demonstration case")
        print("12. Create sample evidence files")
        print("13. Show case summary")
        print("0.  Exit")
        print("=" * 70)

        choice = input("Enter your choice: ").strip()

        try:
            if choice == "1":
                enroll_device(db)
            elif choice == "2":
                enroll_artifact(db)
            elif choice == "3":
                record_custody(db)
            elif choice == "4":
                display_custody(db)
            elif choice == "5":
                verify_checksum(db)
            elif choice == "6":
                create_snapshot(db)
            elif choice == "7":
                cross_check_snapshots(db)
            elif choice == "8":
                assemble_sequence(db)
            elif choice == "9":
                interpret_breach(db)
            elif choice == "10":
                generate_report(db)
            elif choice == "11":
                seed_demo_case(db)
            elif choice == "12":
                create_sample_files()
            elif choice == "13":
                show_case_summary(db)
            elif choice == "0":
                print("Exiting forensic evidence management system.")
                break
            else:
                print("Invalid choice.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
        except Exception as e:
            print(f"Unexpected error: {e}")
            print("The application remains running; check the entered data/path.")


if __name__ == "__main__":
    main()
