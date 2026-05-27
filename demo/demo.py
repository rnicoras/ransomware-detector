from __future__ import annotations
import os
import random
import string
from pathlib import Path

DEMO_DIR = Path("/tmp/demo_target")
HONEYFILE_DIR = Path("/tmp/demo_honeyfiles")

FILENAMES = [
    "Q1_Financial_Report.docx",
    "Employee_Records_2024.xlsx",
    "Project_Roadmap.docx",
    "Client_Contracts.pdf",
    "Personal_Budget.xlsx",
    "Meeting_Notes_March.docx",
    "Source_Code_Backup.zip",
    "Database_Export.csv",
    "Marketing_Strategy.docx",
    "Tax_Returns_2023.pdf",
]

HONEYFILE_NAMES = [
    "passwords.docx",
    "financial_report_2024.xlsx",
    "backup_credentials.txt",
    "company_secrets.pdf",
    "personal_photos.zip",
]

def _make_realistic_content(name: str) -> bytes:
    ext = Path(name).suffix.lower()

    if ext == ".docx":
        text = f"Document: {name}\n" + "Random stuff here. " * 40
        return b"PK\x03\x04" + text.encode()

    if ext == ".xlsx":
        text = f"Spreadsheet: {name}\n" + "Column A, Column B, Column C\n" + "Row. " * 30
        return b"PK\x03\x04" + text.encode()

    if ext == ".pdf":
        text = f"%PDF-1.4\nContent of {name}\n" + "Page content here. " * 40
        return text.encode()

    if ext == ".csv":
        rows = ["id,name,value,date"]
        for i in range(50):
            rows.append(f"{i},Item {i},{random.randint(100,9999)},2024-0{random.randint(1,9)}-01")
        return "\n".join(rows).encode()

    if ext == ".zip":
        return b"PK\x03\x04" + b"\x00" * 100 + b"placeholder zip content " * 10

    text = f"File: {name}\n" + "".join(
        random.choices(string.ascii_letters + " \n", k=800)
    )
    return text.encode()


def setup() -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Creating victim files in {DEMO_DIR} ...")
    for name in FILENAMES:
        path = DEMO_DIR / name
        path.write_bytes(_make_realistic_content(name))
        print(f"  + {name}")

    HONEYFILE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\nCreating honeyfiles in {HONEYFILE_DIR} ...")
    for name in HONEYFILE_NAMES:
        path = HONEYFILE_DIR / name
        path.write_bytes(_make_realistic_content(name))
        print(f"  + {name}")

    print(f"\nDemo environment ready.")
    print(f"Victim files: {DEMO_DIR}")
    print(f"Honeyfiles: {HONEYFILE_DIR}")


if __name__ == "__main__":
    setup()