import os, re, json
import pdfplumber
import docx
import tldextract
from datetime import datetime

reports_dir = "reports"
output_file = "reports_entities.jsonl"

# 正则模式
ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
hash_pattern = re.compile(r'\b[0-9a-fA-F]{32,64}\b')  # MD5 / SHA1 / SHA256
file_pattern = re.compile(r'(?:[A-Za-z]:)?[\\/](?:[\w.-]+[\\/])+[\w.-]+')
time_pattern = re.compile(r'(20\d{2}[-/\.]\d{1,2}[-/\.]\d{1,2}(?:[ T]\d{1,2}:\d{2}:\d{2})?)')

def extract_text(path):
    if path.lower().endswith(".pdf"):
        with pdfplumber.open(path) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)
    elif path.lower().endswith(".docx"):
        doc = docx.Document(path)
        return "\n".join(p.text for p in doc.paragraphs)
    elif path.lower().endswith(".txt"):
        return open(path, encoding="utf-8", errors="ignore").read()
    else:
        return ""

def parse_report(filename, text):
    entities = {
        "ips": list(set(ip_pattern.findall(text))),
        "domains": list(set(domain_pattern.findall(text))),
        "hashes": list(set(hash_pattern.findall(text))),
        "files": list(set(file_pattern.findall(text))),
        "timestamps": list(set(time_pattern.findall(text))),
    }
    # 过滤出有效域名
    entities["domains"] = [
        d for d in entities["domains"] if "." in tldextract.extract(d).suffix
    ]
    return {
        "report_name": filename,
        "entities": entities
    }

if __name__ == "__main__":
    with open(output_file, "w", encoding="utf-8") as out:
        for root, _, files in os.walk(reports_dir):
            for f in files:
                path = os.path.join(root, f)
                text = extract_text(path)
                if not text.strip():
                    continue
                result = parse_report(f, text)
                out.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(f"[+] 实体抽取完成，结果保存在 {output_file}")
