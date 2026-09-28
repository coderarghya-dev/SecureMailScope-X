import os
import re

print("=== File Write Audit ===")
writes = []

for root, dirs, files in os.walk('backend'):
    for f in files:
        if f.endswith('.py') and not f.startswith('test_'):
            p = os.path.join(root, f).replace('\\', '/')
            with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                for idx, line in enumerate(fh, 1):
                    if re.search(r'\b(open\([^)]+[\'"][wa]|joblib\.dump|NamedTemporaryFile|tempfile|TEMP_UPLOAD_DIR|os\.makedirs)\b', line):
                        writes.append((p, idx, line.strip()))

for p, idx, line in writes:
    print(f"{p}:{idx}: {line}")
