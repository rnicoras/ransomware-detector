from __future__ import annotations
import os
import random
import time
from pathlib import Path

DEMO_DIR = Path("/tmp/demo_target")
HONEYFILE_DIR = Path("/tmp/demo_honeyfiles")

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(text: str, colour: str = CYAN) -> None:
    width = 60
    print(f"\n{colour}{BOLD}{'─' * width}{RESET}")
    print(f"{colour}{BOLD}  {text}{RESET}")
    print(f"{colour}{BOLD}{'─' * width}{RESET}\n")


def step(text: str) -> None:
    print(f"{YELLOW}  ▶ {text}{RESET}")


def done(text: str) -> None:
    print(f"{GREEN}  ✓ {text}{RESET}")


def wait(message: str = "Press ENTER to run the next attack stage...") -> None:
    print(f"\n{BOLD}{message}{RESET}")
    input()


def stage_honeyfile() -> None:
    banner("Honeyfile Touch", RED)
    print("Ransomware scanning the filesystem stumbles on a decoy file.")

    target = HONEYFILE_DIR / "passwords.docx"
    if not target.exists():
        print(f"Honeyfile not found at {target}")
        return

    step(f"Opening and writing to honeyfile: {target.name}")
    time.sleep(0.5)

    _ = target.read_bytes()
    target.write_bytes(os.urandom(512))
    done("Honeyfile touched")


def stage_burst() -> None:
    banner("Burst Ops", RED)
    print("Ransomware creates encrypted copies of every file as fast as possible.")

    burst_dir = DEMO_DIR / "burst_files"
    burst_dir.mkdir(exist_ok=True)

    count = 120
    step(f"Creating {count} files as fast as possible...")

    start = time.time()
    for i in range(count):
        path = burst_dir / f"encrypted_{i:04d}.tmp"
        path.write_bytes(os.urandom(256))

    elapsed = time.time() - start
    rate = count / elapsed
    done(f"Created {count} files in {elapsed:.2f}s ({rate:.0f} ops/sec)")
    done("Detector should fire BURST_DETECTED signal")


def stage_entropy() -> None:
    banner("Entropy Spike", RED)
    print("Ransomware overwrites file contents with ciphertext.")
    print("Shannon entropy jumps from ~4.5 (plain text) to ~8.0 (random bytes).\n")

    victim_files = list(DEMO_DIR.glob("*.docx")) + list(DEMO_DIR.glob("*.xlsx"))
    if not victim_files:
        print("No victim files found")
        return

    step(f"Overwriting {len(victim_files)} files with random bytes (simulated ciphertext) ...")
    for path in victim_files:
        path.write_bytes(os.urandom(random.randint(4096, 16384)))
        step(f"Encrypted: {path.name}")
        time.sleep(0.1)

    done("Entropy spike complete")


def stage_rename() -> None:
    banner("Extension Rename", RED)
    print("Ransomware renames every encrypted file to its signature extension.")
    print(".locked is in the known-bad extension list — maximum score contribution.\n")

    targets = list(DEMO_DIR.glob("*.docx")) + list(DEMO_DIR.glob("*.xlsx"))
    if not targets:
        # Files may already have been renamed or entropy-stage created them
        targets = list(DEMO_DIR.glob("*.tmp"))

    if not targets:
        print("No files found to rename")
        return

    step(f"Renaming {len(targets)} files to .locked ...")
    for path in targets:
        new_path = path.with_suffix(".locked")
        path.rename(new_path)
        step(f"Renamed: {path.name} → {new_path.name}")
        time.sleep(0.15)

    done("Renames complete")


def cleanup() -> None:
    banner("CLEANUP", CYAN)
    step("Removing burst files ...")
    burst_dir = DEMO_DIR / "burst_files"
    if burst_dir.exists():
        import shutil
        shutil.rmtree(burst_dir)

    step("Renaming .locked files back to originals ...")
    for path in DEMO_DIR.glob("*.locked"):
        original = path.with_suffix(".docx")
        path.rename(original)

    done("Demo directory restored")


def main() -> None:
    banner("RANSOMWARE DETECTOR DEMO", CYAN)

    wait("Press ENTER to begin Honeyfile Touch...")
    stage_honeyfile()

    wait("Press ENTER to begin Burst File Operations...")
    stage_burst()

    wait("Press ENTER to begin Entropy Spike...")
    stage_entropy()

    wait("Press ENTER to begin Extension Rename...")
    stage_rename()

    banner("ATTACK COMPLETE", RED)

    answer = input("Run cleanup and restore demo files? (y/n): ").strip().lower()
    if answer == "y":
        cleanup()

    print(f"\n{GREEN}{BOLD}Demo finished.{RESET}\n")


if __name__ == "__main__":
    main()