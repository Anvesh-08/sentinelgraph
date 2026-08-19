"""
Deterministic SQL migration runner with SHA-256 checksum verification.
"""
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from backend.app.core.exceptions import SentinelGraphError
from backend.app.core.logging_config import get_logger
from backend.app.db.connection import DatabaseManager

logger = get_logger("sentinelgraph.db.migrator")


class MigrationRunner:
    """Applies and verifies SQL migrations stored in `backend/migrations/`."""

    def __init__(self, db_manager: DatabaseManager, migrations_dir: Path | None = None) -> None:
        self.db = db_manager
        self.migrations_dir = migrations_dir or (Path(__file__).resolve().parents[2] / "migrations")

    def _ensure_migrations_table(self) -> None:
        with self.db.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _compute_checksum(sql_text: str) -> str:
        normalized = sql_text.replace("\r\n", "\n").strip()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def run_migrations(self) -> List[Dict[str, str]]:
        """Executes all pending `.sql` migrations in lexicographical order and verifies existing checksums."""
        self._ensure_migrations_table()
        applied_records: List[Dict[str, str]] = []

        sql_files = sorted(self.migrations_dir.glob("*.sql"))
        with self.db.connection() as conn:
            existing_rows = conn.execute(
                "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC"
            ).fetchall()
            existing_map = {row["version"]: dict(row) for row in existing_rows}

            for sql_file in sql_files:
                stem = sql_file.stem
                parts = stem.split("_", 1)
                version = parts[0]
                name = parts[1] if len(parts) > 1 else stem
                sql_content = sql_file.read_text(encoding="utf-8")
                checksum = self._compute_checksum(sql_content)

                if version in existing_map:
                    recorded_checksum = existing_map[version]["checksum"]
                    if recorded_checksum != checksum:
                        raise SentinelGraphError(
                            f"Migration checksum mismatch for version {version} ({name}).",
                            error_code="MIGRATION_CHECKSUM_MISMATCH",
                            details={"version": version, "expected": recorded_checksum, "actual": checksum},
                        )
                    continue

                conn.executescript(sql_content)
                conn.execute("PRAGMA foreign_keys = ON;")
                applied_at = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                    (version, name, checksum, applied_at),
                )
                record = {"version": version, "name": name, "checksum": checksum, "applied_at": applied_at}
                applied_records.append(record)
                logger.info(f"Applied database migration {version}_{name} (checksum={checksum[:12]})")

        return applied_records

    def list_applied_migrations(self) -> List[Dict[str, str]]:
        self._ensure_migrations_table()
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC"
            ).fetchall()
            return [dict(r) for r in rows]
