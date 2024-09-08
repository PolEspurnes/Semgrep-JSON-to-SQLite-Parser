import json
import sqlite3
import argparse


def manage_args():
	parser = argparse.ArgumentParser(description="Process input and output file names.")
	
	# Input file argument (mandatory)
	parser.add_argument('input_file', help="Name of the semgrep.json results file.")
	
	# Output file argument (optional with a default value)
	parser.add_argument('-o', '--output_file', default='scan_results.db', help="Name of the output SQLite DB file (default: scan_results.db)")
	
	return parser.parse_args()


def create_database(conn):
	cursor = conn.cursor()

	# Reset tables
	cursor.execute('DROP TABLE IF EXISTS findings;')
	cursor.execute('DROP TABLE IF EXISTS rules;')

	cursor.execute('''
			CREATE TABLE rules (
				rule_name TEXT PRIMARY KEY,
				reference TEXT NOT NULL,
				description TEXT NOT NULL,
				cwe TEXT NOT NULL,
				vulnerability_class TEXT NOT NULL,
				technology TEXT NOT NULL
			)
		''')

	cursor.execute('''
		CREATE TABLE findings (
			id INTEGER PRIMARY KEY,
			semgrep_rule TEXT NOT NULL,
			file TEXT NOT NULL,
			line INTEGER,
			code TEXT NOT NULL,
			confidence INTEGER,
			FOREIGN KEY(semgrep_rule) REFERENCES rules(rule_name)
		)
	''')

	conn.commit()
	cursor.close()


def insert_rules(conn, data):
	cursor = conn.cursor()
	for rule, details in data.items():
		cursor.execute('''
			INSERT INTO rules (rule_name, reference, description, cwe, vulnerability_class, technology)
			VALUES (?, ?, ?, ?, ?, ?);
		''', (rule, details['reference'], details['description'], details['cwe'], details['vulnerability_class'], details['technology']))

	conn.commit()
	cursor.close()


def insert_findings(conn, data):
	cursor = conn.cursor()
	for result in data:
		cursor.execute('''
			INSERT INTO findings (semgrep_rule, file, line, code, confidence)
			VALUES (?, ?, ?, ?, ?);
		''', (result['semgrep_rule'], result['file'], result['line'], result['code'], result['confidence']))


	conn.commit()
	cursor.close()


args = manage_args()

with open(args.input_file, 'r') as scan_file:
	data = json.loads(scan_file.read())

	findings = []
	rules = {}


	for result in data['results']:
		findings.append({
			'semgrep_rule': result['check_id'],
			'file': result['path'],
			'line': result['start']['line'],
			'code': result['extra']['lines'],
			'confidence': 3 if result['extra']['metadata']['confidence'] == 'HIGH' else 2 if result['extra']['metadata']['confidence'] == 'MEDIUM' else 1
			})

		if result['check_id'] not in rules:
			rules[result['check_id']] = {
				'description': result['extra']['message'],
				'reference': result['extra']['metadata']['shortlink'],
				'cwe': result['extra']['metadata']['cwe'][0],
				'vulnerability_class': result['extra']['metadata']['vulnerability_class'][0],
				'technology': result['extra']['metadata']['technology'][0]
			}



	conn = sqlite3.connect(args.output_file)
	create_database(conn)
	insert_rules(conn, rules)
	insert_findings(conn, findings)
	conn.close()