"""Extract all text from thesis.pdf and save to a text file."""
from PyPDF2 import PdfReader
import os

reader = PdfReader(r'd:\web_attack_detector\thesis.pdf')
out_path = r'd:\web_attack_detector\scratch\thesis_full_text.txt'

with open(out_path, 'w', encoding='utf-8') as f:
    f.write(f"Total pages: {len(reader.pages)}\n\n")
    for i, page in enumerate(reader.pages):
        text = page.extract_text()
        if text:
            f.write(f"\n{'='*60}\n")
            f.write(f"PAGE {i+1}\n")
            f.write(f"{'='*60}\n")
            f.write(text)
            f.write("\n")

print(f"Done. Written to {out_path}")
print(f"Total pages: {len(reader.pages)}")
