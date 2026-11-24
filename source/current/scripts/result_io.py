from pathlib import Path
import csv

def load_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def save_csv(path, rows):
    if not rows:
        raise ValueError("No rows to save")
    with Path(path).open("w", encoding="utf-8", newline="") as f:
        writer=csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
