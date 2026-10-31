"""URL selection for SQLite and Neon Postgres. The schema check uses a local file."""
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import inspect
from sqlalchemy.pool import NullPool

from backend.database import (
    build_engine,
    direct_postgres_url,
    is_postgres_url,
    normalize_database_url,
)
from backend.schema import ensure_schema


class DatabaseUrlTests(unittest.TestCase):
    def test_empty_url_stays_on_sqlite(self):
        url = normalize_database_url("", data_dir=Path("/tmp/sentinel-url"))
        self.assertEqual(url, "sqlite:////tmp/sentinel-url/sentinel.db")
        self.assertFalse(is_postgres_url(url))

    def test_sqlite_url_is_unchanged(self):
        raw = "sqlite:////tmp/custom.db"
        self.assertEqual(normalize_database_url(raw), raw)

    def test_postgres_and_postgresql_use_psycopg(self):
        pooled = normalize_database_url(
            "postgres://app:secret@ep-test-pooler.us-east-1.aws.neon.tech/sentinel"
        )
        self.assertTrue(pooled.startswith("postgresql+psycopg://"))
        self.assertIn("sslmode=require", pooled)
        self.assertIn("-pooler.", pooled)
        direct = direct_postgres_url(pooled)
        self.assertNotIn("-pooler.", direct)
        self.assertIn("ep-test.us-east-1.aws.neon.tech", direct)
        self.assertIn("sslmode=require", direct)
        explicit = normalize_database_url(
            "postgresql://app:secret@db.example/sentinel?sslmode=require"
        )
        self.assertTrue(explicit.startswith("postgresql+psycopg://"))
        self.assertEqual(explicit.count("sslmode"), 1)
        self.assertEqual(direct_postgres_url(explicit), explicit)

    def test_other_schemes_are_rejected(self):
        with self.assertRaises(RuntimeError):
            normalize_database_url("mysql://app:secret@localhost/sentinel")

    def test_postgres_engine_does_not_use_sqlite_connect_args(self):
        engine = build_engine("postgresql+psycopg://app:secret@127.0.0.1/sentinel")
        self.addCleanup(engine.dispose)
        self.assertIsInstance(engine.pool, NullPool)
        self.assertEqual(engine.dialect.name, "postgresql")

    def test_schema_creates_auth_and_inventory_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = build_engine("sqlite:///" + str(Path(tmp) / "schema.db"))
            self.addCleanup(engine.dispose)
            ensure_schema(bind=engine)
            names = set(inspect(engine).get_table_names())
        for table in ("clients", "servers", "auth_users", "auth_sessions", "encrypted_ssh_credentials"):
            self.assertIn(table, names)


if __name__ == "__main__":
    unittest.main()
