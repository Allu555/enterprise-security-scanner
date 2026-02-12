
# ============================================================================
# database.py - Database Operations
# ============================================================================
import sqlite3
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, List, Optional, Any
import hashlib
import bcrypt
import secrets

DB_PATH = "security_scanner.db"

@contextmanager
def get_db_connection():
    """Get database connection with context manager"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_database():
    """Initialize all database tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')
        
        # User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_valid INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Activity logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                target_url TEXT NOT NULL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                pages_crawled INTEGER DEFAULT 0,
                vulnerabilities_found INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0,
                scan_results TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # System settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
            )
        ''')
        
        # Insert default admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            password_hash = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, full_name, role)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', 'admin@securityscanner.com', password_hash, 'System Administrator', 'admin'))
        
        # Insert default settings
        default_settings = [
            ('max_scan_duration', '3600'),
            ('max_pages_per_scan', '100'),
            ('enable_ai_analysis', 'true'),
            ('maintenance_mode', 'false'),
            ('registration_enabled', 'true'),
            ('session_timeout', '24'),
        ]
        
        for key, value in default_settings:
            cursor.execute('''
                INSERT OR IGNORE INTO system_settings (key, value)
                VALUES (?, ?)
            ''', (key, value))

# ============================================================================
# USER OPERATIONS - COMPLETED WITH ALL FUNCTIONS
# ============================================================================
class UserDB:
    """User database operations"""
    
    @staticmethod
    def create_user(username: str, email: str, password: str, full_name: str = None, role: str = 'user') -> Dict:
        """Create new user"""
        try:
            # Validate inputs
            if len(password) < 6:
                raise ValueError("Password must be at least 6 characters")
            
            if not username or not email:
                raise ValueError("Username and email are required")
            
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, role)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, email, password_hash, full_name, role))
                
                user_id = cursor.lastrowid
                
                return {
                    'id': user_id,
                    'username': username,
                    'email': email,
                    'full_name': full_name,
                    'role': role,
                    'is_active': 1
                }
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                raise ValueError("Username already exists")
            elif 'email' in str(e):
                raise ValueError("Email already registered")
            else:
                raise e
    
    @staticmethod
    def authenticate_user(username: str, password: str) -> Optional[Dict]:
        """Authenticate user credentials"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM users 
                WHERE (username = ? OR email = ?)
            ''', (username, username))
            
            user = cursor.fetchone()
            
            if not user:
                return None
            
            # Check if account is active
            if not user['is_active']:
                raise ValueError("Account is deactivated. Contact administrator.")
            
            # Check if account is locked
            if user['locked_until']:
                try:
                    locked_until = datetime.fromisoformat(user['locked_until'])
                    if locked_until > datetime.now():
                        raise ValueError(f"Account locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')}")
                except (ValueError, TypeError):
                    # If locked_until is invalid, treat as not locked
                    pass
            
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                # Reset failed attempts on successful login
                cursor.execute('''
                    UPDATE users 
                    SET last_login = ?, failed_attempts = 0, locked_until = NULL
                    WHERE id = ?
                ''', (datetime.now().isoformat(), user['id']))
                
                return dict(user)
            else:
                # Increment failed attempts
                failed = user['failed_attempts'] + 1
                locked_until = None
                
                # Lock account after 5 failed attempts
                if failed >= 5:
                    locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                
                cursor.execute('''
                    UPDATE users 
                    SET failed_attempts = ?, locked_until = ?
                    WHERE id = ?
                ''', (failed, locked_until, user['id']))
                
                return None
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def get_user_by_username(username: str) -> Optional[Dict]:
        """Get user by username"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict]:
        """Get user by email"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def update_user(user_id: int, **kwargs) -> bool:
        """Update user information"""
        allowed_fields = ['full_name', 'email', 'role', 'is_active']
        updates = []
        values = []
        
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates.append(f"{key} = ?")
                values.append(value)
        
        if not updates:
            return False
        
        values.append(user_id)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                UPDATE users 
                SET {', '.join(updates)}
                WHERE id = ?
            ''', values)
            
            return cursor.rowcount > 0
    
    @staticmethod
    def change_password(user_id: int, old_password: str, new_password: str) -> bool:
        """Change user password"""
        if len(new_password) < 6:
            raise ValueError("New password must be at least 6 characters")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                return False
            
            if bcrypt.checkpw(old_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
                return True
            
            return False
    
    @staticmethod
    def admin_reset_password(user_id: int, new_password: str) -> bool:
        """Admin force reset user password"""
        if len(new_password) < 6:
            raise ValueError("Password must be at least 6 characters")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('UPDATE users SET password_hash = ?, failed_attempts = 0 WHERE id = ?', 
                         (new_hash, user_id))
            return cursor.rowcount > 0
    
    @staticmethod
    def unlock_user_account(user_id: int) -> bool:
        """Unlock a locked user account"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET locked_until = NULL, failed_attempts = 0 
                WHERE id = ?
            ''', (user_id,))
            return cursor.rowcount > 0
    
    @staticmethod
    def delete_user(user_id: int) -> bool:
        """Delete a user permanently"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            return cursor.rowcount > 0
    
    @staticmethod
    def get_all_users() -> List[Dict]:
        """Get all users (admin only)"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, full_name, role, is_active, 
                       created_at, last_login, failed_attempts, locked_until
                FROM users 
                ORDER BY id DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    @staticmethod
    def get_active_users_count() -> int:
        """Get count of active users"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1')
            return cursor.fetchone()['count']
    
    @staticmethod
    def search_users(search_term: str) -> List[Dict]:
        """Search users by username or email"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, full_name, role, is_active, created_at
                FROM users 
                WHERE username LIKE ? OR email LIKE ? OR full_name LIKE ?
                ORDER BY username
                LIMIT 50
            ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
            return [dict(row) for row in cursor.fetchall()]

# ============================================================================
# SESSION OPERATIONS
# ============================================================================
class SessionDB:
    """Session management"""
    
    @staticmethod
    def create_session(user_id: int, ip_address: str = None, user_agent: str = None) -> str:
        """Create new session"""
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, token, ip_address, user_agent, expires_at))
        
        return token
    
    @staticmethod
    def validate_session(token: str) -> Optional[Dict]:
        """Validate session token"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT s.*, u.username, u.role, u.email, u.is_active
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ? AND s.is_valid = 1 AND s.expires_at > ? AND u.is_active = 1
            ''', (token, datetime.now().isoformat()))
            
            session = cursor.fetchone()
            return dict(session) if session else None
    
    @staticmethod
    def invalidate_session(token: str) -> bool:
        """Invalidate session"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE sessions SET is_valid = 0 WHERE token = ?', (token,))
            return cursor.rowcount > 0
    
    @staticmethod
    def invalidate_all_user_sessions(user_id: int) -> bool:
        """Invalidate all sessions for a user"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE sessions SET is_valid = 0 WHERE user_id = ?', (user_id,))
            return True
    
    @staticmethod
    def get_active_sessions(user_id: int = None) -> List[Dict]:
        """Get active sessions"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute('''
                    SELECT * FROM sessions 
                    WHERE user_id = ? AND is_valid = 1 AND expires_at > ?
                    ORDER BY created_at DESC
                ''', (user_id, datetime.now().isoformat()))
            else:
                cursor.execute('''
                    SELECT s.*, u.username, u.email
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.is_valid = 1 AND s.expires_at > ?
                    ORDER BY s.created_at DESC
                    LIMIT 100
                ''', (datetime.now().isoformat(),))
            
            return [dict(row) for row in cursor.fetchall()]
    
    @staticmethod
    def clean_expired_sessions() -> int:
        """Delete expired sessions"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE expires_at <= ?', 
                         (datetime.now().isoformat(),))
            return cursor.rowcount

# ============================================================================
# ACTIVITY LOGS - COMPLETED
# ============================================================================
class ActivityLog:
    """Activity logging operations"""
    
    @staticmethod
    def log(user_id: Optional[int], username: Optional[str], action: str, 
            resource_type: str = None, resource_id: str = None, 
            details: Dict = None, status: str = "success",
            ip_address: str = None, user_agent: str = None):
        """Log user activity"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO activity_logs 
                    (user_id, username, action, resource_type, resource_id, details, status, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, username, action, resource_type, resource_id,
                    json.dumps(details) if details else None,
                    status, ip_address, user_agent
                ))
        except Exception as e:
            print(f"Failed to log activity: {e}")
    
    @staticmethod
    def get_user_activity(user_id: int, limit: int = 50) -> List[Dict]:
        """Get activity for specific user"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM activity_logs 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (user_id, limit))
            
            activities = []
            for row in cursor.fetchall():
                activity = dict(row)
                if activity['details']:
                    try:
                        activity['details'] = json.loads(activity['details'])
                    except:
                        activity['details'] = {}
                activities.append(activity)
            
            return activities
    
    @staticmethod
    def get_all_activity(limit: int = 100) -> List[Dict]:
        """Get all activity (admin only)"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM activity_logs 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            
            activities = []
            for row in cursor.fetchall():
                activity = dict(row)
                if activity['details']:
                    try:
                        activity['details'] = json.loads(activity['details'])
                    except:
                        activity['details'] = {}
                activities.append(activity)
            
            return activities
    
    @staticmethod
    def get_activity_by_action(action: str, limit: int = 50) -> List[Dict]:
        """Get activity by action type"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM activity_logs 
                WHERE action = ?
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (action, limit))
            
            activities = []
            for row in cursor.fetchall():
                activity = dict(row)
                if activity['details']:
                    try:
                        activity['details'] = json.loads(activity['details'])
                    except:
                        activity['details'] = {}
                activities.append(activity)
            
            return activities
    
    @staticmethod
    def get_system_stats() -> Dict:
        """Get system statistics"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as count FROM users')
            total_users = cursor.fetchone()['count']
            
            cursor.execute('''
                SELECT COUNT(DISTINCT user_id) as count 
                FROM activity_logs 
                WHERE created_at > ? AND user_id IS NOT NULL
            ''', ((datetime.now() - timedelta(hours=24)).isoformat(),))
            active_users = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM scan_history')
            total_scans = cursor.fetchone()['count']
            
            cursor.execute('SELECT IFNULL(SUM(vulnerabilities_found), 0) as total FROM scan_history')
            total_vulns = cursor.fetchone()['total'] or 0
            
            cursor.execute('''
                SELECT COUNT(*) as count 
                FROM activity_logs 
                WHERE action = 'login' AND status = 'failed'
                AND created_at > ?
            ''', ((datetime.now() - timedelta(hours=24)).isoformat(),))
            failed_logins = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1')
            active_accounts = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM users WHERE locked_until IS NOT NULL')
            locked_accounts = cursor.fetchone()['count']
            
            return {
                'total_users': total_users,
                'active_users_24h': active_users,
                'active_accounts': active_accounts,
                'locked_accounts': locked_accounts,
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulns,
                'failed_logins_24h': failed_logins,
                'timestamp': datetime.now().isoformat()
            }
    
    @staticmethod
    def clean_old_logs(days: int = 30) -> int:
        """Delete logs older than specified days"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM activity_logs WHERE created_at < ?', (cutoff_date,))
            return cursor.rowcount

# ============================================================================
# SCAN HISTORY OPERATIONS - COMPLETED
# ============================================================================
class ScanHistoryDB:
    """Scan history operations"""
    
    @staticmethod
    def save_scan(scan_result, user_id: int, username: str):
        """Save scan result to database"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            scan_data = {
                'scan_id': scan_result.scan_id,
                'target_url': scan_result.target_url,
                'start_time': scan_result.start_time.isoformat() if scan_result.start_time else None,
                'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
                'pages_crawled': scan_result.pages_crawled,
                'vulnerabilities': [
                    {
                        'vuln_id': getattr(v, 'vuln_id', None),
                        'type': getattr(v, 'type', 'Unknown'),
                        'name': getattr(v, 'name', 'Unknown'),
                        'severity': getattr(v, 'severity', 'Unknown'),
                        'cvss_score': getattr(v, 'cvss_score', 0),
                        'cwe': getattr(v, 'cwe', None),
                        'location': getattr(v, 'location', None)
                    }
                    for v in getattr(scan_result, 'vulnerabilities', [])
                ],
                'subdomains': list(getattr(scan_result, 'subdomains', [])),
                'open_ports': getattr(scan_result, 'open_ports', []),
                'risk_score': getattr(scan_result, 'risk_score', 0)
            }
            
            cursor.execute('''
                INSERT INTO scan_history 
                (scan_id, user_id, username, target_url, start_time, end_time, 
                 status, pages_crawled, vulnerabilities_found, risk_score, scan_results)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result.scan_id,
                user_id,
                username,
                scan_result.target_url,
                scan_result.start_time.isoformat() if scan_result.start_time else None,
                scan_result.end_time.isoformat() if scan_result.end_time else None,
                getattr(scan_result, 'status', 'completed'),
                getattr(scan_result, 'pages_crawled', 0),
                len(getattr(scan_result, 'vulnerabilities', [])),
                getattr(scan_result, 'risk_score', 0),
                json.dumps(scan_data)
            ))
    
    @staticmethod
    def get_user_scans(user_id: int, limit: int = 20) -> List[Dict]:
        """Get scans for specific user"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, target_url, start_time, end_time, status, 
                       pages_crawled, vulnerabilities_found, risk_score
                FROM scan_history 
                WHERE user_id = ? 
                ORDER BY start_time DESC 
                LIMIT ?
            ''', (user_id, limit))
            
            scans = []
            for row in cursor.fetchall():
                scan = dict(row)
                scans.append(scan)
            
            return scans
    
    @staticmethod
    def get_all_scans(limit: int = 100) -> List[Dict]:
        """Get all scans (admin only)"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, username, target_url, start_time, end_time, 
                       status, pages_crawled, vulnerabilities_found, risk_score
                FROM scan_history 
                ORDER BY start_time DESC 
                LIMIT ?
            ''', (limit,))
            
            scans = []
            for row in cursor.fetchall():
                scan = dict(row)
                scans.append(scan)
            
            return scans
    
    @staticmethod
    def get_scan_by_id(scan_id: str) -> Optional[Dict]:
        """Get specific scan by ID"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scan_history WHERE scan_id = ?', (scan_id,))
            scan = cursor.fetchone()
            
            if scan:
                result = dict(scan)
                if result['scan_results']:
                    try:
                        result['scan_results'] = json.loads(result['scan_results'])
                    except:
                        result['scan_results'] = {}
                return result
            
            return None
    
    @staticmethod
    def get_user_scan_stats(user_id: int) -> Dict:
        """Get scan statistics for a user"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) as total_scans,
                       SUM(vulnerabilities_found) as total_vulns,
                       AVG(risk_score) as avg_risk,
                       MAX(risk_score) as max_risk
                FROM scan_history 
                WHERE user_id = ?
            ''', (user_id,))
            
            stats = dict(cursor.fetchone())
            
            cursor.execute('''
                SELECT COUNT(*) as count
                FROM scan_history 
                WHERE user_id = ? AND DATE(start_time) = DATE('now')
            ''', (user_id,))
            
            stats['scans_today'] = cursor.fetchone()['count']
            
            return stats
    
    @staticmethod
    def delete_scan(scan_id: str) -> bool:
        """Delete a scan record"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scan_history WHERE scan_id = ?', (scan_id,))
            return cursor.rowcount > 0

# ============================================================================
# SYSTEM SETTINGS OPERATIONS - NEW
# ============================================================================
class SystemSettingsDB:
    """System settings operations"""
    
    @staticmethod
    def get_setting(key: str, default: str = None) -> Optional[str]:
        """Get a system setting"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM system_settings WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row['value'] if row else default
    
    @staticmethod
    def set_setting(key: str, value: str, updated_by: int = None) -> bool:
        """Set a system setting"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO system_settings (key, value, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
            ''', (key, value, datetime.now().isoformat(), updated_by))
            return cursor.rowcount > 0
    
    @staticmethod
    def get_all_settings() -> Dict:
        """Get all system settings"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM system_settings ORDER BY key')
            return {row['key']: row['value'] for row in cursor.fetchall()}
    
    @staticmethod
    def delete_setting(key: str) -> bool:
        """Delete a system setting"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM system_settings WHERE key = ?', (key,))
            return cursor.rowcount > 0
    
    @staticmethod
    def is_maintenance_mode() -> bool:
        """Check if system is in maintenance mode"""
        value = SystemSettingsDB.get_setting('maintenance_mode', 'false')
        return value.lower() == 'true'
    
    @staticmethod
    def is_registration_enabled() -> bool:
        """Check if user registration is enabled"""
        value = SystemSettingsDB.get_setting('registration_enabled', 'true')
        return value.lower() == 'true'

# Initialize database on module import
init_database()
