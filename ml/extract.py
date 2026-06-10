from __future__ import annotations
import csv
import math
import os
import sys
from pathlib import Path

DATASET_DIR = Path("C:/Users/User/Desktop/napierone")

_MAGIC: dict[str, list[bytes]] = {
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
    ".pptx": [b"PK\x03\x04"],
    ".doc":  [b"\xd0\xcf\x11\xe0"],
    ".xls":  [b"\xd0\xcf\x11\xe0"],
    ".ppt":  [b"\xd0\xcf\x11\xe0"],
    ".pdf":  [b"%PDF"],
    ".png":  [b"\x89PNG"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".zip":  [b"PK\x03\x04", b"PK\x05\x06"],
    ".gz":   [b"\x1f\x8b"],
    ".7z":   [b"7z\xbc\xaf"],
    ".rar":  [b"Rar!"],
}

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def chi_square(data: bytes) -> float:
    # measure how uniform the byte distribution is; if it's perfectly uniform (encrypted) means low chi_square per byte
    # structured data = high chi_square
    if not data:
        return 0.0
    length = len(data)
    expected = length / 256.0
    if expected == 0:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    chi_sq = sum((f - expected) ** 2 / expected for f in freq)
    return chi_sq / length # normalize by length so we can compare across file sizes

def header_matches_magicbyte(data: bytes, extension: str) -> bool:
    # check if file header matches expected magic bytes for the extension
    extension = extension.lower()
    expected_list = _MAGIC.get(extension)
    if expected_list is None:
        return False # unknown extension
    for expected in expected_list:
        if data[:len(expected)] == expected:
            return True
    return False

def detect_original_extension(filepath: Path, is_ransomware: bool) -> str:
    if not is_ransomware:
        return filepath.suffix.lower()
    stem = filepath.stem
    original = Path(stem).suffix.lower()
    return original if original else filepath.suffix.lower()

def extract_features(filepath: Path, is_ransomware: bool) -> dict | None:
    try:
        data = filepath.read_bytes()
    except OSError:
        return None
    
    if len(data) == 0:
        return None
    
    extension = detect_original_extension(filepath, is_ransomware)
    return {
        "entropy": round(shannon_entropy(data), 4),
        "filesize": len(data),
        "chi_square": round(chi_square(data), 4),
        "magicbyte": 1 if header_matches_magicbyte(data, extension) else 0,
        "original_extension": extension,
        "label": 1 if is_ransomware else 0,
        "source": filepath.name,
    }
    
def process_directory(directory: Path, is_ransomware: bool, type: str) -> list[dict]:
    results = []
    files = [f for f in directory.iterdir() if f.is_file()]
    total = len(files)
    for i, filepath in enumerate(files, 1):
        features = extract_features(filepath, is_ransomware)
        if features:
            results.append(features)
        if i % 100 == 0 or i == total:
            print(f"[{type}] {i}/{total} files processed")
    return results

def main():
    benign_dir = DATASET_DIR / "benign"
    ransomware_dir = DATASET_DIR / "ransomware"

    if not benign_dir.exists() or not ransomware_dir.exists():
        print("One of the following directories is missing: ")
        print(f"{benign_dir}")
        print(f"{ransomware_dir}")
        sys.exit(1)

    all_features = []

    for subdir in sorted(benign_dir.iterdir()):
        if subdir.is_dir():
            print(f"Processing benign {subdir.name}")
            features = process_directory(subdir, is_ransomware=False, type=subdir.name)
            all_features.extend(features)
            print(f"{len(features)} features extracted")

    for subdir in sorted(ransomware_dir.iterdir()):
        if subdir.is_dir():
            print(f"Processing ransomware {subdir.name}")
            features = process_directory(subdir, is_ransomware=True, type=subdir.name)
            all_features.extend(features)
            print(f"{len(features)} features extracted")

    output = DATASET_DIR / "features.csv"
    fields = ["entropy", "filesize", "chi_square", "magicbyte", "original_extension", "label", "source"]
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(all_features)

    benign_count = sum(1 for f in all_features if f["label"] == 0)
    ransomware_count = sum(1 for f in all_features if f["label"] == 1)
    print(f"Benign: {benign_count}")
    print(f"Ransomware: {ransomware_count}")

if __name__ == "__main__":
    main()