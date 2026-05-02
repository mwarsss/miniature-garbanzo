"""
Database connection management with connection pooling and migrations.
"""
import datetime
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator, Optional
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


# ---------------------------------------------------------------------------
# GitHubScanEvent — typed container for webhook-triggered pipeline runs
# ---------------------------------------------------------------------------

@dataclass
class GitHubScanEvent:
    """
    Records every webhook-triggered pipeline run for the scan history feed.

    pipeline_status values
    ----------------------
    "success"     — pipeline completed, patches committed (possibly 0)
    "partial"     — pipeline ran but some steps failed gracefully
    "no_findings" — scan produced zero findings; no patches generated
    "error"       — pipeline raised an unhandled exception
    """

    repo_full_name: str
    pr_number: int
    pr_head_sha: str
    installation_id: int
    triggered_at: datetime.datetime
    findings_count: int
    patches_committed: int
    child_pr_number: Optional[int]
    child_pr_url: Optional[str]
    pipeline_status: str   # "success" | "partial" | "no_findings" | "error"
    error_message: Optional[str]
    id: Optional[int] = None


def log_github_scan_event(database_url: str, event: GitHubScanEvent) -> Optional[int]:
    """
    Insert a GitHubScanEvent row into github_scan_events.

    Opens its own connection (not from the pool) so it can be called from
    background tasks without requiring pool access. Never raises — all errors
    are logged and None is returned so the pipeline continues cleanly.

    Returns the inserted row id, or None on failure.
    """
    try:
        conn = psycopg2.connect(database_url)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO github_scan_events (
                repo_full_name, pr_number, pr_head_sha, installation_id,
                triggered_at, findings_count, patches_committed,
                child_pr_number, child_pr_url, pipeline_status, error_message
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                event.repo_full_name,
                event.pr_number,
                event.pr_head_sha,
                event.installation_id,
                event.triggered_at,
                event.findings_count,
                event.patches_committed,
                event.child_pr_number,
                event.child_pr_url,
                event.pipeline_status,
                event.error_message,
            ),
        )
        row = cur.fetchone()
        conn.commit()
        inserted_id = row[0] if row else None
        logger.debug("Logged GitHubScanEvent id=%s for %s PR #%d",
                     inserted_id, event.repo_full_name, event.pr_number)
        return inserted_id
    except Exception as exc:
        logger.error("Failed to log GitHubScanEvent (non-fatal): %s", exc)
        return None
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass


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
        
        # Ensure error_message column exists for older table versions
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scans' AND column_name='error_message') THEN
                    ALTER TABLE scans ADD COLUMN error_message TEXT;
                END IF;
            END $$;
        """)

        # Add commit_sha and repo_full_name for GitHub commit status reporting
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scans' AND column_name='commit_sha') THEN
                    ALTER TABLE scans ADD COLUMN commit_sha VARCHAR(40);
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scans' AND column_name='repo_full_name') THEN
                    ALTER TABLE scans ADD COLUMN repo_full_name VARCHAR(255);
                END IF;
            END $$;
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

        # Enforcement rules / scan policies table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_policies (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                severity_threshold VARCHAR(50) NOT NULL DEFAULT 'HIGH',
                block_on_failure BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        # Seed default rules if table is empty
        cur.execute("SELECT COUNT(*) FROM scan_policies")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO scan_policies (name, description, enabled, severity_threshold, block_on_failure) VALUES
                ('No Critical Vulnerabilities', 'Fails scan if any Critical severity issues are found.', TRUE, 'CRITICAL', TRUE),
                ('No High Severity Secrets', 'Blocks deployment if hardcoded secrets or API keys are detected.', TRUE, 'HIGH', TRUE),
                ('OWASP Top 10 Compliance', 'Flags any finding mapped to the OWASP Top 10 (2021) categories.', TRUE, 'MEDIUM', FALSE),
                ('Dependency Age Check', 'Warns when vulnerable components with known CVEs are used.', TRUE, 'HIGH', FALSE)
                ON CONFLICT DO NOTHING;
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

        # GitHub App webhook-triggered scan history
        cur.execute("""
            CREATE TABLE IF NOT EXISTS github_scan_events (
                id                SERIAL PRIMARY KEY,
                repo_full_name    VARCHAR(255) NOT NULL,
                pr_number         INTEGER NOT NULL,
                pr_head_sha       VARCHAR(64) NOT NULL,
                installation_id   INTEGER NOT NULL,
                triggered_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                findings_count    INTEGER NOT NULL DEFAULT 0,
                patches_committed INTEGER NOT NULL DEFAULT 0,
                child_pr_number   INTEGER,
                child_pr_url      TEXT,
                pipeline_status   VARCHAR(50) NOT NULL DEFAULT 'success',
                error_message     TEXT
            );
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_github_scan_events_repo
                ON github_scan_events(repo_full_name);
            CREATE INDEX IF NOT EXISTS idx_github_scan_events_triggered_at
                ON github_scan_events(triggered_at DESC);
            CREATE INDEX IF NOT EXISTS idx_github_scan_events_pr
                ON github_scan_events(repo_full_name, pr_number);
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
