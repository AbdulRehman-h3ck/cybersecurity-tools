import sqlite3
import datetime

class ThreatDatabase:
    def __init__(self, db_name="threat_intel.db"):
        self.db_name = db_name
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # 1. Base table create karte hain agar bilkul exist nahi karti
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            )
        ''')
        
        # 2. 🔥 ULTRA-SMART MIGRATION: Check all columns aur jo missing hain unhe add karo
        cursor.execute("PRAGMA table_info(scan_history)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        # Yeh saare columns hamari database mein hone chahiye
        columns_to_ensure = {
            'date': "TEXT DEFAULT 'Unknown'",
            'package_name': "TEXT DEFAULT 'Unknown'",
            'score': "INTEGER DEFAULT 0",
            'verdict': "TEXT DEFAULT 'Unknown'",
            'confidence': "TEXT DEFAULT 'Unknown'",
            'traits': "TEXT DEFAULT 'None'",
            'cert_hash': "TEXT DEFAULT 'UNKNOWN'"
        }
        
        # Jo column missing hai, use automatically Alter table karke add kar do
        for col, col_type in columns_to_ensure.items():
            if col not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE scan_history ADD COLUMN {col} {col_type}")
                except Exception as e:
                    pass # Ignore minor alteration errors
                    
        conn.commit()
        conn.close()

    def save_scan(self, package_name, score, verdict, confidence, traits_list, cert_hash="UNKNOWN"):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        traits_str = ", ".join(traits_list) if traits_list else "None"
        
        cursor.execute('''
            INSERT INTO scan_history (date, package_name, score, verdict, confidence, traits, cert_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (date_str, package_name, score, verdict, confidence, traits_str, cert_hash))
        conn.commit()
        conn.close()

    def get_all_scans(self):
        conn = sqlite3.connect(self.db_name)
        # 🔥 Magic: Ab hum columns ko index ki jagah unke naam se access karenge
        conn.row_factory = sqlite3.Row 
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scan_history ORDER BY id DESC')
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for r in rows:
            # Safe extraction taake app kabhi crash na kare
            results.append({
                'date': r['date'] if 'date' in r.keys() else 'Unknown',
                'package_name': r['package_name'] if 'package_name' in r.keys() else 'Unknown',
                'score': r['score'] if 'score' in r.keys() else 0,
                'verdict': r['verdict'] if 'verdict' in r.keys() else 'Unknown',
                'confidence': r['confidence'] if 'confidence' in r.keys() else 'Unknown',
                'traits': r['traits'] if 'traits' in r.keys() else 'None',
                'cert_hash': r['cert_hash'] if 'cert_hash' in r.keys() else 'UNKNOWN'
            })
        return results

    def check_cert_family(self, cert_hash):
        """Returns previous packages that used the SAME certificate (Clustering)"""
        if cert_hash in ["UNKNOWN", "UNSIGNED_OR_NOT_FOUND"] or cert_hash.startswith("ERROR"):
            return []
            
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Sirf existing columns nikalenge jo clustering ke liye chahiye
        cursor.execute('SELECT package_name, verdict, date FROM scan_history WHERE cert_hash = ?', (cert_hash,))
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for r in rows:
            results.append({
                "package_name": r['package_name'] if 'package_name' in r.keys() else 'Unknown',
                "verdict": r['verdict'] if 'verdict' in r.keys() else 'Unknown',
                "date": r['date'] if 'date' in r.keys() else 'Unknown'
            })
        return results
