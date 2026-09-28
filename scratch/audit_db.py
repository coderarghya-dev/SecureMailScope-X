import os
import re

print("=== Detail of INSERT OR REPLACE / IGNORE ===")
files_to_check = [
    'backend/app/db/repository.py',
    'backend/app/services/case_service.py',
    'backend/app/services/alerting_service.py',
    'backend/app/services/remediation_service.py',
    'backend/app/services/monitoring_service.py',
    'backend/app/services/pqc_migration_service.py',
    'backend/app/services/rbac_service.py'
]

for fp in files_to_check:
    if os.path.exists(fp):
        with open(fp, 'r', encoding='utf-8') as f:
            for idx, line in enumerate(f, 1):
                if re.search(r'INSERT\s+OR\s+(REPLACE|IGNORE)', line, re.I):
                    print(f"{fp}:{idx}: {line.strip()}")
