import PyPDF2

pdf = PyPDF2.PdfReader(r"d:\web_attack_detector\research_paper_final__2___1_.pdf")
pages = len(pdf.pages)
print(f"Total pages: {pages}")
print()

# Full section structure
for i in range(pages):
    text = pdf.pages[i].extract_text() or ""
    lines = text.split("\n")
    
    # Find section headings
    for l in lines:
        s = l.strip()
        # Match roman numeral sections
        if any(s.upper().startswith(x) for x in ["I. ", "II.", "III.", "IV.", "V.", "VI.", "VII.", "VIII.", "IX.", "X.", "XI."]):
            if len(s) < 80 and len(s) > 4:
                print(f"  P{i+1}: SECTION: {s}")
        # Match lettered subsections  
        if any(s.startswith(x) for x in ["A. ", "B. ", "C. ", "D. ", "E. ", "F. ", "G. ", "H. "]):
            if len(s) < 80 and len(s) > 4:
                print(f"  P{i+1}:   SUB: {s}")
        # Find figure captions
        if s.startswith("Fig."):
            print(f"  P{i+1}: FIGURE: {s[:80]}")
        # Find table captions
        if s.startswith("TABLE"):
            print(f"  P{i+1}: TABLE: {s[:80]}")
        # Find broken refs
        if "??" in s:
            print(f"  P{i+1}: BROKEN REF: {s[:80]}")
        # Find Algorithm
        if s.startswith("Algorithm"):
            print(f"  P{i+1}: ALGO: {s[:80]}")

# Check for missing section references
print("\n=== REFERENCE ISSUES ===")
all_text = ""
for i in range(pages):
    all_text += pdf.pages[i].extract_text() or ""

if "??" in all_text:
    print("WARNING: Found '??' - broken references exist!")
else:
    print("OK: No broken references found")

# Check figure count
fig_count = all_text.count("Fig.")
print(f"Figure mentions: {fig_count}")

# Check for FUTURE WORK spacing issue
if "FUTUREWORK" in all_text:
    print("WARNING: 'FUTUREWORK' spacing issue in section title")
if "ETHICALCONSIDERATIONS" in all_text:
    print("WARNING: 'ETHICALCONSIDERATIONS' spacing issue in section title")
