import urllib.request
import json
import os

boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
pcap_path = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"
with open(pcap_path, 'rb') as f:
    file_bytes = f.read()

body = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="file"; filename="smtp-starttls-test.pcapng"\r\n'
    f'Content-Type: application/octet-stream\r\n\r\n'
).encode('utf-8') + file_bytes + f'\r\n--{boundary}--\r\n'.encode('utf-8')

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/analyze',
    data=body,
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
    method='POST'
)

with urllib.request.urlopen(req) as resp:
    res = json.loads(resp.read().decode('utf-8'))
    analysis_id = res.get('analysis_id')
    print('POST /analyze successful. ID:', analysis_id)

with urllib.request.urlopen(f'http://127.0.0.1:8000/api/v1/analyze/{analysis_id}') as resp2:
    data = json.loads(resp2.read().decode('utf-8'))
    print('=== GET /analyze/{id} RESPONSE VALUES ===')
    print('top-level evidence_confidence_score:', data.get('evidence_confidence_score'))
    print('top-level evidence_confidence_level:', data.get('evidence_confidence_level'))
    s0 = data.get('sessions', [{}])[0]
    ec = s0.get('evidence_confidence', {})
    print('sessions[0].evidence_confidence.score:', ec.get('score'))
    print('sessions[0].evidence_confidence.level:', ec.get('level'))
    print('=== HNDL & PQC FINDINGS IN SESSIONS ===')
    for s in data.get('sessions', []):
        sec = s.get('security_assessment', {})
        for f in sec.get('findings', []):
            if 'PQC' in f.get('id', '') or 'HNDL' in f.get('id', '') or 'Quantum' in f.get('title', '') or 'Harvest' in f.get('title', ''):
                print('Finding ID:', f.get('id'))
                print('Title:', f.get('title'))
                print('Description:', f.get('description'))
                print('Severity:', f.get('severity'))
