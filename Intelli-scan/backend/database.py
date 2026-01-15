"""
Database connection management with connection pooling and migrations.
"""
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from typing import Generator
import logging

logger = logging.getLogger(__name__)


class DatabasePool:
    """Database connection pool manager."""
    
    def __init__(self, database_url: str, min_conn: int = 1, max_conn: int = 10):
        """Initialize connection pool."""
        try:
            self.pool = psycopg2.pool.ThreadedConnectionPool(
                min_conn,
                max_conn,
                database_url
            )
            logger.info(f"✅ Database pool created (min={min_conn}, max={max_conn})")
        except psycopg2.Error as e:
            logger.error(f"❌ Failed to create database pool: {e}")
            raise
    
    @contextmanager
    def get_connection(self) -> Generator:
        """Get a connection from the pool."""
        conn = None
        try:
            conn = self.pool.getconn()
            yield conn
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                self.pool.putconn(conn)
    
    @contextmanager
    def get_cursor(self, cursor_factory=RealDictCursor) -> Generator:
        """Get a cursor from a pooled connection."""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Transaction failed: {e}")
                raise
            finally:
                cursor.close()
    
    def close_all(self):
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("Database pool closed")


def create_tables(database_url: str):
    """Create database tables with proper indexes and constraints."""
    conn = psycopg2.connect(database_url)
    cur = conn.cursor()
    
    try:
        # Scans table with indexes
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                uuid UUID UNIQUE NOT NULL,
                repo_url VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL,
                submit_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                finished_at TIMESTAMPTZ,
                sca_result JSONB,
                sast_result JSONB,
                ai_analysis JSONB,
                error_message TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        
        # Create indexes for performance
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_uuid ON scans(uuid);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_submit_time ON scans(submit_time DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_repo_url ON scans(repo_url);
        """)
        
        # Policy documents table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS policy_documents (
                id SERIAL PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        
        # Reports table with foreign key
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                format VARCHAR(50) NOT NULL,
                filename VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
            CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at DESC);
        """)
        
        # Audit log table for tracking changes
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                entity_type VARCHAR(50) NOT NULL,
                entity_id INTEGER NOT NULL,
                action VARCHAR(50) NOT NULL,
                changes JSONB,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
        """)
        
        conn.commit()
        logger.info("✅ Database tables and indexes created successfully")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Failed to create tables: {e}")
        raise
    finally:
        cur.close()
        conn.close()
