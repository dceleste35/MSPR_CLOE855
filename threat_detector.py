from datetime import datetime, timedelta
import json
import sqlite3

class ThreatDetector:
    def __init__(self, db_path='database.db'):
        self.db_path = db_path
        self.thresholds = {
            'login_attempts': 5,
            'timeframe': 300,
            'suspicious_chars': ['<script>', 'union select', '--', ';', '=\'']
        }

    def get_recent_failures(self, ip_address, minutes=5):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timeframe = (datetime.now() - timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S')

        print(timeframe, ip_address)

        cursor.execute('''
            SELECT COUNT(*) FROM connection_logs
            WHERE ip_address = ?
            AND success = 0
        ''', (ip_address, timeframe))

        count = cursor.fetchone()[0]
        conn.close()
        return count

    def check_login_attempt(self, username, ip_address):
        failures = self.get_recent_failures(ip_address)
        print(failures)
        if failures >= self.thresholds['login_attempts']:
            self.log_threat(
                'BRUTE_FORCE',
                ip_address,
                f"Multiple login failures: {failures} in 5 minutes",
                'HIGH'
            )
            return False
        return True

    def check_input(self, user_input, ip_address):
        for pattern in self.thresholds['suspicious_chars']:
            if pattern in user_input.lower():
                self.log_threat(
                    'INJECTION_ATTEMPT',
                    ip_address,
                    f"Suspicious pattern detected: {pattern}",
                    'HIGH'
                )
                return False
        return True

    def log_threat(self, threat_type, ip_address, details, severity):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO security_threats
            (threat_type, ip_address, details, severity)
            VALUES (?, ?, ?, ?)
        ''', (threat_type, ip_address, details, severity))

        conn.commit()
        conn.close()
