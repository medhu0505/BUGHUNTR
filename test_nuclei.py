import requests
import json
import time

# Test nuclei scanner
response = requests.post('http://localhost:5000/api/scans/run',
                        json={'moduleId': 'nuclei', 'target': 'example.com'},
                        timeout=30)
print('Status:', response.status_code)

if response.status_code == 200:
    data = response.json()
    print('Scan ID:', data.get('scan_id'))

    # Wait for scan to complete
    scan_id = data.get('scan_id')
    for i in range(10):  # Wait up to 50 seconds
        time.sleep(5)
        result_response = requests.get(f'http://localhost:5000/api/results/{scan_id}')
        if result_response.status_code == 200:
            results = result_response.json()
            print('Findings:', len(results))
            for finding in results[:3]:  # Show first 3
                print(f'  - {finding.get("finding")} ({finding.get("severity")})')
            break
        else:
            print(f'Waiting... attempt {i+1}')
else:
    print('Response:', response.text[:500])