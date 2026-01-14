import sqlite3
import hashlib
import os
import requests

DB_FILE = "signatures.db"

class SignatureEngine:
    def __init__(self, db_path):
        self.db_path = os.path.join(db_path, DB_FILE)
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS signatures
                     (hash TEXT PRIMARY KEY, name TEXT, severity TEXT)''')
        
        # Seed with some known test signatures (EICAR, etc.)
        # In prod, this would sync with a Cloud Threat Intel feed
        c.execute("INSERT OR IGNORE INTO signatures VALUES (?, ?, ?)", 
                  ("44d88612fea8a8f36de82e1278abb02f", "EICAR-Test-File", "Critical"))
        # Add WannaCry hash example
        c.execute("INSERT OR IGNORE INTO signatures VALUES (?, ?, ?)", 
                  ("24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1922c", "WannaCry.Ransomware", "Critical"))
        
        conn.commit()
        conn.close()

    def get_file_hash(self, file_path):
        """Calculates SHA256 of a file efficiently"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None

    def scan_hash(self, file_path):
        """Returns threat name if hash is found in DB"""
        f_hash = self.get_file_hash(file_path)
        if not f_hash: return None
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT name FROM signatures WHERE hash=?", (f_hash,))
        result = c.fetchone()
        conn.close()
        
        return result[0] if result else None

    def update_definitions(self):
        """Pulls latest hashes from backend (Mocked)"""
        # print("Updating Virus Definitions...")
        pass