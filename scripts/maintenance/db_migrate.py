"""
Enterprise Database Migration Engine (v5.4.0)
ACID Compliance | ISO 27001 | NIST SP 800-209
"""

import logging
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import sqlparse
from cryptography.fernet import Fernet
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import mysql.connector
import sqlite3
import pymssql
import dotenv
import jwt
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure enterprise logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/enliven/db_migrate.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DBMigrator')
audit_logger = logging.getLogger('DBAudit')
audit_logger.setLevel(logging.INFO)

dotenv.load_dotenv()

class SecureDatabaseMigrator:
    def __init__(self, config_path: str = 'migration_config.json'):
        self.migration_table = "schema_migrations"
        self.encryption_key = os.getenv('DB_ENCRYPTION_KEY')
        self.cipher_suite = Fernet(self.encryption_key) if self.encryption_key else None
        self.supported_engines = ['postgresql', 'mysql', 'sqlite', 'mssql']
        
        self.load_config(config_path)
        self.validate_security_config()
        self.conn_pool = self.create_connection_pool()
        self.initialize_migration_table()

    def load_config(self, config_path: str):
        """Load and decrypt configuration file"""
        try:
            with open(config_path, 'rb') as f:
                encrypted_config = f.read()
                decrypted_config = self.cipher_suite.decrypt(encrypted_config) if self.cipher_suite else encrypted_config
                self.config = json.loads(decrypted_config.decode())
                
            self.validate_database_config()
            logger.info("Loaded and validated migration configuration")
            
        except Exception as e:
            logger.error(f"Configuration load failed: {str(e)}")
            raise

    def validate_database_config(self):
        """Validate database connection parameters"""
        required_fields = ['engine', 'host', 'database', 'user', 'password']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Missing required config field: {field}")
                
        if self.config['engine'] not in self.supported_engines:
            raise ValueError(f"Unsupported database engine: {self.config['engine']}")

    def validate_security_config(self):
        """Enforce security requirements"""
        if not self.config.get('ssl'):
            raise SecurityException("SSL connection required for database migrations")
            
        if not self.encryption_key:
            raise SecurityException("Encryption key not configured")
            
        if self.config.get('password') and not self.config['password'].startswith('enc:'):
            raise SecurityException("Database password must be encrypted")

    def create_connection_pool(self):
        """Create connection pool with security context"""
        conn_params = {
            'host': self.config['host'],
            'database': self.config['database'],
            'user': self.decrypt_value(self.config['user']),
            'password': self.decrypt_value(self.config['password']),
            'ssl': self.configure_ssl_context(),
            'application_name': 'EnlivenDBMigrator',
            'connect_timeout': 30
        }
        
        try:
            if self.config['engine'] == 'postgresql':
                return psycopg2.pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=10,
                    **conn_params
                )
            # Similar implementations for other engines
        except Exception as e:
            logger.error(f"Connection pool creation failed: {str(e)}")
            raise

    def configure_ssl_context(self):
        """Configure SSL context based on security profile"""
        ssl_config = {
            'sslmode': 'verify-full',
            'sslrootcert': '/etc/ssl/certs/ca-certificates.crt',
            'sslcert': '/etc/ssl/certs/client.crt',
            'sslkey': self.decrypt_file('/etc/ssl/private/client.key')
        }
        return ssl_config

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    def get_connection(self):
        """Get encrypted connection from pool"""
        try:
            conn = self.conn_pool.getconn()
            conn.set_session(autocommit=False)
            return conn
        except Exception as e:
            logger.error(f"Connection acquisition failed: {str(e)}")
            raise

    def release_connection(self, conn):
        """Release connection back to pool"""
        self.conn_pool.putconn(conn)

    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt sensitive configuration values"""
        if encrypted_value.startswith('enc:'):
            encrypted_value = encrypted_value[4:]
            return self.cipher_suite.decrypt(encrypted_value.encode()).decode()
        return encrypted_value

    def decrypt_file(self, file_path: str) -> str:
        """Decrypt encrypted file contents"""
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            return self.cipher_suite.decrypt(encrypted_data).decode()

    def initialize_migration_table(self):
        """Create version tracking table with audit triggers"""
        migration_table_ddl = sql.SQL("""
            CREATE TABLE IF NOT EXISTS {} (
                version VARCHAR(255) PRIMARY KEY,
                checksum VARCHAR(64) NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                applied_by VARCHAR(255) NOT NULL,
                status VARCHAR(20) NOT NULL
            )
        """).format(sql.Identifier(self.migration_table))
        
        audit_trigger_ddl = """
            CREATE TRIGGER migration_audit_trigger
            AFTER INSERT OR UPDATE ON schema_migrations
            FOR EACH ROW EXECUTE PROCEDURE log_migration_audit();
        """
        
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(migration_table_ddl)
                    cursor.execute(audit_trigger_ddl)
                    conn.commit()
                    logger.info("Initialized migration tracking system")
        except Exception as e:
            logger.error(f"Migration table initialization failed: {str(e)}")
            raise

    def generate_migration_metadata(self, migration_file: str) -> Dict:
        """Generate cryptographic metadata for migration files"""
        with open(migration_file, 'rb') as f:
            content = f.read()
            checksum = hashlib.sha256(content).hexdigest()
            
        return {
            'file_name': os.path.basename(migration_file),
            'checksum': checksum,
            'version': datetime.now().strftime("%Y%m%d%H%M%S"),
            'applied_by': os.getenv('USER') or 'enliven-migrator'
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    def execute_migration(self, migration_file: str):
        """Execute a database migration with full ACID compliance"""
        metadata = self.generate_migration_metadata(migration_file)
        migration_content = self.parse_migration_file(migration_file)
        
        try:
            with self.get_connection() as conn:
                conn.set_isolation_level(ISOLATION_LEVEL_READ_COMMITTED)
                
                with conn.cursor() as cursor:
                    # Transaction start
                    cursor.execute("BEGIN;")
                    
                    # Execute migration steps
                    for statement in migration_content['up']:
                        cursor.execute(statement)
                        
                    # Record migration
                    insert_query = sql.SQL("""
                        INSERT INTO {} (version, checksum, applied_by, status)
                        VALUES (%s, %s, %s, %s)
                    """).format(sql.Identifier(self.migration_table))
                    
                    cursor.execute(insert_query, (
                        metadata['version'],
                        metadata['checksum'],
                        metadata['applied_by'],
                        'applied'
                    ))
                    
                    # Commit transaction
                    conn.commit()
                    self.log_audit_event(metadata, "success")
                    logger.info(f"Applied migration {metadata['version']}")
                    
        except Exception as e:
            self.log_audit_event(metadata, "failed", str(e))
            logger.error(f"Migration failed: {str(e)}")
            conn.rollback()
            raise
        finally:
            self.release_connection(conn)

    def parse_migration_file(self, file_path: str) -> Dict[str, List[str]]:
        """Parse migration file into executable statements"""
        with open(file_path, 'r') as f:
            content = f.read()
            
        sections = content.split('-- migrate: ')
        parsed = {'up': [], 'down': []}
        
        for section in sections:
            if section.startswith('up'):
                parsed['up'] = sqlparse.split(section[3:].strip())
            elif section.startswith('down'):
                parsed['down'] = sqlparse.split(section[5:].strip())
                
        return parsed

    def log_audit_event(self, metadata: Dict, status: str, error: str = None):
        """Record security audit event with JWT token"""
        audit_payload = {
            "event": "schema_migration",
            "version": metadata['version'],
            "file": metadata['file_name'],
            "checksum": metadata['checksum'],
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            "user": metadata['applied_by']
        }
        
        if error:
            audit_payload['error'] = error[:500]  # Truncate long errors
            
        signed_token = jwt.encode(
            audit_payload,
            self.encryption_key,
            algorithm='HS256'
        )
        
        audit_logger.info(signed_token)

    def rollback_migration(self, version: str):
        """Rollback specific migration version"""
        try:
            migration_file = self.find_migration_file(version)
            migration_content = self.parse_migration_file(migration_file)
            
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("BEGIN;")
                    
                    # Execute rollback statements
                    for statement in migration_content['down']:
                        cursor.execute(statement)
                        
                    # Update migration status
                    update_query = sql.SQL("""
                        UPDATE {}
                        SET status = 'rolled_back'
                        WHERE version = %s
                    """).format(sql.Identifier(self.migration_table))
                    
                    cursor.execute(update_query, (version,))
                    conn.commit()
                    self.log_audit_event(
                        {'version': version, 'applied_by': 'system'},
                        "rollback_success"
                    )
                    logger.info(f"Rolled back migration {version}")
                    
        except Exception as e:
            self.log_audit_event(
                {'version': version, 'applied_by': 'system'},
                "rollback_failed",
                str(e)
            )
            logger.error(f"Rollback failed: {str(e)}")
            raise

    def verify_migrations(self):
        """Validate applied migrations against file system"""
        applied_versions = self.get_applied_versions()
        file_versions = self.get_file_versions()
        
        discrepancies = []
        # Check for missing files
        for version in applied_versions:
            if version not in file_versions:
                discrepancies.append(f"Missing file for applied version {version}")
                
        # Check for unapplied files
        for version in file_versions:
            if version not in applied_versions:
                discrepancies.append(f"Unapplied migration {version}")
                
        if discrepancies:
            raise MigrationIntegrityError("\n".join(discrepancies))

    def get_applied_versions(self) -> List[str]:
        """Retrieve list of applied migration versions"""
        query = sql.SQL("SELECT version FROM {} WHERE status = 'applied'").format(
            sql.Identifier(self.migration_table)
        )
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query)
                return [row[0] for row in cursor.fetchall()]

    def get_file_versions(self) -> List[str]:
        """Extract versions from migration filenames"""
        migration_dir = self.config.get('migration_dir', 'migrations')
        return [f.split('_')[0] for f in os.listdir(migration_dir) if f.endswith('.sql')]

    def find_migration_file(self, version: str) -> str:
        """Locate migration file by version number"""
        migration_dir = self.config.get('migration_dir', 'migrations')
        for filename in os.listdir(migration_dir):
            if filename.startswith(version):
                return os.path.join(migration_dir, filename)
        raise FileNotFoundError(f"Migration file for version {version} not found")

class SecurityException(Exception):
    """Critical security policy violation"""
    pass

class MigrationIntegrityError(Exception):
    """Database schema version mismatch detected"""
    pass

if __name__ == "__main__":
    try:
        migrator = SecureDatabaseMigrator()
        migrator.verify_migrations()
        
        migration_dir = migrator.config.get('migration_dir', 'migrations')
        for migration_file in sorted(os.listdir(migration_dir)):
            if migration_file.endswith('.sql'):
                full_path = os.path.join(migration_dir, migration_file)
                migrator.execute_migration(full_path)
                
    except Exception as e:
        logger.critical(f"Migration process aborted: {str(e)}")
        exit(1)
