"""
BENSEC - Web Application Security Scanner & WAF
Database Models Engine Configuration Handler.
"""

import os
import sqlite3

# Dynamically map path frames relative to this module's location
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.db")

def get_db_connection():
    """Initializes a safe connection handle to the SQLite back-end file."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Builds foundational system schema structures if not present."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Core Targets Monitoring Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        scan_status TEXT DEFAULT 'pending',
        risk_score INTEGER DEFAULT 0,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Core Vulnerability Logging Track Matrix
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        vuln_type TEXT,
        severity TEXT,
        affected_url TEXT,
        parameter TEXT,
        payload TEXT,
        description TEXT,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(target_id) REFERENCES targets(id)
    );
    """)
    
    # WAF Intercept Rules Logging Deck
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS waf_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        attack_type TEXT,
        request_path TEXT,
        payload TEXT,
        action_taken TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    conn.commit()
    conn.close()

def add_target(url):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO targets (url) VALUES (?)", (url,))
        conn.commit()
        target_id = cursor.lastrowid
        cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
        row = cursor.fetchone()
        conn.close()
        return row
    except sqlite3.IntegrityError:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM targets WHERE url = ?", (url,))
        row = cursor.fetchone()
        conn.close()
        return row
    except Exception:
        return None

def get_all_targets():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_target(target_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def update_target_status(target_id, status, risk_score=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if risk_score is not None:
        cursor.execute("UPDATE targets SET scan_status = ?, risk_score = ? WHERE id = ?", (status, risk_score, target_id))
    else:
        cursor.execute("UPDATE targets SET scan_status = ? WHERE id = ?", (status, target_id))
    conn.commit()
    conn.close()

def add_vulnerability(target_id, vuln_type, severity, affected_url, parameter=None, payload=None, description=None):
    """Inserts a discovered flaw and forces an immediate transaction write."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO vulnerabilities (target_id, vuln_type, severity, affected_url, parameter, payload, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_id, vuln_type, severity, affected_url, parameter, payload, description))
        conn.commit()
        conn.close()
        print(f"[DB SUCCESS] Logged {vuln_type} vulnerability for target ID {target_id}")
    except Exception as e:
        print(f"[DB ERROR] Failed logging vulnerability: {e}")
        if conn:
            conn.close()

def get_vulnerabilities(target_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if target_id:
        cursor.execute("SELECT * FROM vulnerabilities WHERE target_id = ? ORDER BY id DESC", (target_id,))
    else:
        cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_vuln_stats():
    """Calculates metrics by securely linking vulnerabilities to existing targets."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT COUNT(v.id) as total FROM vulnerabilities v
        INNER JOIN targets t ON v.target_id = t.id
    """)
    total = cursor.fetchone()['total'] or 0
    
    cursor.execute("""
        SELECT COUNT(v.id) as high FROM vulnerabilities v
        INNER JOIN targets t ON v.target_id = t.id
        WHERE v.severity IN ('Critical', 'High')
    """)
    high = cursor.fetchone()['high'] or 0
    
    cursor.execute("""
        SELECT COUNT(v.id) as medium FROM vulnerabilities v
        INNER JOIN targets t ON v.target_id = t.id
        WHERE v.severity = 'Medium'
    """)
    medium = cursor.fetchone()['medium'] or 0
    
    cursor.execute("""
        SELECT COUNT(v.id) as low FROM vulnerabilities v
        INNER JOIN targets t ON v.target_id = t.id
        WHERE v.severity = 'Low'
    """)
    low = cursor.fetchone()['low'] or 0
    
    cursor.execute("SELECT COUNT(*) as blocked FROM waf_logs")
    blocked = cursor.fetchone()['blocked'] or 0
    
    conn.close()
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked": blocked
    }

def get_waf_logs(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM waf_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_waf_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM waf_logs")
    total = cursor.fetchone()['total'] or 0
    
    cursor.execute("SELECT attack_type, COUNT(*) as count FROM waf_logs GROUP BY attack_type")
    by_type = cursor.fetchall()
    
    cursor.execute("SELECT ip_address, COUNT(*) as count FROM waf_logs GROUP BY ip_address ORDER BY count DESC LIMIT 5")
    top_ips = cursor.fetchall()
    
    conn.close()
    return {
        "total": total,
        "by_type": by_type,
        "top_ips": top_ips
    }

def log_waf_attack(ip_address, attack_type, request_path, payload, action_taken='Blocked'):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO waf_logs (ip_address, attack_type, request_path, payload, action_taken)
    VALUES (?, ?, ?, ?, ?)
    """, (ip_address, attack_type, request_path, payload, action_taken))
    conn.commit()
    conn.close()

def get_request_logs(limit=200):
    return []

def get_blacklist():
    return []

def blacklist_ip(ip_address, attack_type, block_reason, permanent=False):
    pass

def remove_from_blacklist(ip):
    pass

def delete_target_and_history(target_id: int) -> bool:
    """Permanently purges targets and dependencies cleanly across an exclusive transaction commit."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA foreign_keys = OFF;")
        cursor.execute("BEGIN IMMEDIATE TRANSACTION;")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = [row['name'].lower() for row in cursor.fetchall()]

        # Automatically wipe vulnerability logs for this target
        for table_variant in ["vulnerabilities", "vulnerability", "vulns", "vuln"]:
            if table_variant in existing_tables:
                cursor.execute(f"DELETE FROM {table_variant} WHERE target_id = ?;", (target_id,))

        # Wipe target entity configuration entries
        if "targets" in existing_tables:
            cursor.execute("DELETE FROM targets WHERE id = ?;", (target_id,))
        elif "target" in existing_tables:
            cursor.execute("DELETE FROM target WHERE id = ?;", (target_id,))
            
        cursor.execute("COMMIT;")
        conn.close()
        return True
    except Exception:
        if conn:
            try:
                conn.execute("ROLLBACK;")
                conn.close()
            except Exception:
                pass
        return False

# ── Alias Bindings & Missing WAF Imports ──────────────────────────────────────
add_waf_log = log_waf_attack

def is_blacklisted(ip):
    return False

def add_request_log(*args, **kwargs):
    pass