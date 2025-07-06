import sqlite3
import sys
import os

def db_stuff(filename, sha256, entropy, file_size):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "av-cli.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("" \
    "CREATE TABLE IF NOT EXISTS scanned_files "
    "(" \
    "id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "filename TEXT," \
    "sha256 TEXT UNIQUE," \
    "entropy REAL," \
    "file_size INTEGER," \
    "timestamp_scanned DATETIME DEFAULT CURRENT_TIMESTAMP" \
    ")")
    cursor.execute("""
        INSERT INTO scanned_files (filename, sha256, entropy, file_size)
        VALUES (?, ?, ?, ?)
    """, (filename, sha256, entropy, file_size))

    conn.commit()
    conn.close()

def main():
    filename = sys.argv[1].strip()
    sha256 = sys.argv[2].strip()
    entropy = float(sys.argv[3])
    file_size = int(sys.argv[4])
    try:
        db_stuff(filename, sha256, entropy, file_size)
    except:
        None

if __name__ == "__main__":
    main()
    print("> Database stored in database folder")

