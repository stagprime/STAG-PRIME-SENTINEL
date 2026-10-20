"""Local administrator bootstrap, without hardcoded accounts or passwords.

From project root: .venv\\Scripts\\python.exe -m backend.auth_cli bootstrap-admin
"""
import argparse
import getpass
import sys
from sqlalchemy import select

from backend.auth_models import AuthUser, create_auth_tables
from backend.auth_security import hash_password, normalize_username, validate_password
from backend.database import SessionLocal


def bootstrap_admin() -> int:
    create_auth_tables()
    with SessionLocal() as db:
        # Only the *first* admin is bootstrapped this way. Future management
        # requires a protected administrative workflow.
        if db.scalar(select(AuthUser.id).where(AuthUser.role == "admin").limit(1)):
            print("STOP: An administrator already exists. No changes made.")
            return 1
        print("=== STAG PRIME SENTINEL: FIRST ADMIN SETUP ===")
        print("Use a unique username and strong passphrase. Input is local to this terminal.")
        try:
            username = normalize_username(input("Admin username: "))
            display_name = input("Display name: ").strip()
            if not 2 <= len(display_name) <= 120:
                raise ValueError("Display name must be 2-120 characters")
            password = getpass.getpass("New admin password (hidden): ")
            confirm = getpass.getpass("Confirm password (hidden): ")
            if password != confirm:
                raise ValueError("Passwords do not match")
            validate_password(password, username)
            user = AuthUser(
                username=username, display_name=display_name,
                password_hash=hash_password(password), role="admin", is_active=True,
            )
            db.add(user)
            db.commit()
            print("SUCCESS: First administrator created. Password is never printed or stored in plain text.")
            print("Existing client/server inventory was not changed.")
            return 0
        except (ValueError, EOFError, KeyboardInterrupt) as err:
            print(f"STOP: {err if not isinstance(err, KeyboardInterrupt) else 'Cancelled'}")
            return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Local auth initialization (do not expose remotely)")
    parser.add_argument("action", choices=["bootstrap-admin"])
    args = parser.parse_args()
    if args.action == "bootstrap-admin":
        return bootstrap_admin()
    return 2


if __name__ == "__main__":
    sys.exit(main())
