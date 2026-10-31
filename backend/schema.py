"""Create Sentinel tables on SQLite or Postgres. Safe to run more than once."""


def ensure_schema(bind=None) -> None:
    import backend.admin_access  # noqa: F401
    import backend.auth_models  # noqa: F401
    import backend.command_preflight  # noqa: F401
    import backend.controlled_jobs  # noqa: F401
    import backend.credential_vault  # noqa: F401
    import backend.inventory_bulk  # noqa: F401
    import backend.monitoring_engine  # noqa: F401
    import backend.onboarding_scan  # noqa: F401
    import backend.openvpn_profiles  # noqa: F401
    import backend.user_management  # noqa: F401
    from backend.database import Base, schema_engine

    if bind is not None:
        Base.metadata.create_all(bind=bind)
        return
    target, owned = schema_engine()
    try:
        Base.metadata.create_all(bind=target)
    finally:
        if owned:
            target.dispose()
