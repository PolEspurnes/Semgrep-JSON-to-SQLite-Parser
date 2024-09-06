import json
import sqlite3

with open('../example_semgrep_scan.json', 'r') as scan_file:
	data = json.loads(scan_file.read())

	results = []

	for result in data['results']:
		results.append({
			'check_id': result['check_id'],
			'file': result['path'],
			'line': result['start']['line'],
			'code': result['extra']['lines'],
			'vulnerability_class': result['extra']['metadata']['vulnerability_class'][0],
			'confidence': 1 if result['extra']['metadata']['confidence'] == 'HIGH' else 2 if result['extra']['metadata']['confidence'] == 'MEDIUM' else 3
			})

	print(results)
	print(len(results))