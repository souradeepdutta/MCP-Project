import sqlite3
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "soc_db.sqlite"

def init_db():
    """Initialize the new normalized SOC database."""
    # Remove the old db if you want to start fresh (uncomment if needed)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # 1. Employees Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Employees (
                employee_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                risk_level TEXT DEFAULT 'Standard'
            )
        ''')

        # 2. Assets (Laptops) Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Assets (
                asset_id TEXT PRIMARY KEY,
                employee_id TEXT,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                FOREIGN KEY (employee_id) REFERENCES Employees(employee_id)
            )
        ''')

        # 3. Emails Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Emails (
                email_id INTEGER PRIMARY KEY AUTOINCREMENT,
                internal_mailpit_id TEXT UNIQUE,
                message_id TEXT,
                sender TEXT,
                subject TEXT,
                received_at TEXT,
                status TEXT DEFAULT 'Pending'
            )
        ''')

        # 4. Investigations (Cases) Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Investigations (
                case_id TEXT PRIMARY KEY,
                email_id INTEGER,
                verdict TEXT,
                severity TEXT,
                summary TEXT,
                technical_details TEXT,
                recommended_actions TEXT,
                created_at TEXT,
                FOREIGN KEY (email_id) REFERENCES Emails(email_id)
            )
        ''')

        # -- SEED DUMMY DATA --
        # Check if employees exist before inserting
        cursor.execute("SELECT COUNT(*) FROM Employees")
        if cursor.fetchone()[0] == 0:
            employees_data = [
                ('EMP-001', 'John Doe', 'jdoe@yourcompany.com', 'Standard'),
                ('EMP-002', 'Jane Smith', 'jsmith@yourcompany.com', 'Standard'),
                ('EMP-003', 'Alice Executive', 'alice.exec@yourcompany.com', 'VIP'),
                ('EMP-004', 'Chris Jones', 'cjones@yourcompany.com', 'High-Risk')
            ]
            cursor.executemany("INSERT INTO Employees VALUES (?, ?, ?, ?)", employees_data)

            assets_data = [
                ('AST-100', 'EMP-001', 'LAPTOP-JDOE', '10.0.0.5'),
                ('AST-101', 'EMP-002', 'LAPTOP-JSMITH', '10.0.0.12'),
                ('AST-102', 'EMP-003', 'LAPTOP-AEXEC', '10.0.0.8'),
                ('AST-103', 'EMP-004', 'LAPTOP-CJONES', '10.0.0.22')
            ]
            cursor.executemany("INSERT INTO Assets VALUES (?, ?, ?, ?)", assets_data)
            
        conn.commit()
        print(f"Database initialized successfully at {DB_PATH}")

if __name__ == "__main__":
    init_db()
