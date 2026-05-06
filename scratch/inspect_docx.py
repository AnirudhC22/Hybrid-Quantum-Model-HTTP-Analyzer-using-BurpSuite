import docx

doc_path = r'd:\web_attack_detector\Journal_Paper_Hybrid_Quantum_Web_Attack_Detector_Humanized.docx'

try:
    doc = docx.Document(doc_path)
    text = []
    for p in doc.paragraphs:
        if p.text.strip():
            text.append(p.text)
    
    full_text = "\n".join(text)
    word_count = len(full_text.split())
    
    print(f"Total Paragraphs: {len(text)}")
    print(f"Total Words: {word_count}")
    print(f"Estimated Pages (250 words/page): {word_count / 250:.1f}")
    
    print("\n--- Snippet of content (first 1000 chars) ---")
    print(full_text[:1000])
    
    print("\n--- Snippet of content (last 1000 chars) ---")
    print(full_text[-1000:])
    
except Exception as e:
    print(f"Error reading docx: {e}")
