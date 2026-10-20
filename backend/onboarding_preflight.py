"""Read-only onboarding readiness for any number of inventory servers.

No SSH requests, sudo, installation, certificate handling, or remote changes.
An inventory entry is NOT an authorization to contact that host.
"""
from __future__ import annotations

from typing import Any


def describe_onboarding(*, server_id: str, server_name: str, client: str,
                        host: str, ssh_username: str | None, ssh_port: int,
                        monitoring_configured: bool, monitoring_enabled: bool,
                        local_configuration_ready: bool,
                        missing_settings: list[str],
                        admin_profile_ready: bool = False,
                        admin_profile_present: bool = False) -> dict[str, Any]:
    has_identity = bool(host and host.strip() and ssh_username and ssh_username.strip()
                        and isinstance(ssh_port, int) and 1 <= ssh_port <= 65535)
    needs_approval = not (admin_profile_ready or (monitoring_configured and monitoring_enabled))
    if not has_identity:
        phase = 'inventory_incomplete'
        next_step = 'Complete server IP/hostname, SSH username and SSH port in Server Inventory.'
    elif needs_approval:
        phase = 'approval_required'
        next_step = 'SSH credentials and host identity must be securely enrolled and explicitly approved by an administrator.'
    elif not (admin_profile_ready or local_configuration_ready):
        phase = 'configuration_attention'
        next_step = 'Review monitoring profile mismatch or missing backend-only SSH files before any remote discovery.'
    else:
        phase = 'eligible_for_read_only_discovery'
        next_step = ('Encrypted administrator credential is ready. Verify live SSH identity, then run read-only OpenVPN detection.'
                     if admin_profile_ready else
                     'Monitoring identity is ready; separate administrator enrollment is required for installation and repair.')
    # Do not forward private-key path or other detailed internal diagnostics.
    return {
        'server_id': server_id,
        'server_name': server_name,
        'client': client,
        'host': host,
        'phase': phase,
        'checks': {
            'inventory_identity_complete': has_identity,
            'monitoring_profile_approved': bool(monitoring_configured and monitoring_enabled),
            'admin_credential_ready': bool(admin_profile_ready),
            'admin_credential_enrolled': bool(admin_profile_present),
            'local_configuration_ready': bool(admin_profile_ready or local_configuration_ready),
            'remote_ssh_test_performed': False,
            'remote_openvpn_discovery_performed': False,
            'installation_performed': False,
        },
        'next_step': next_step,
        'administrative_approval_required': not admin_profile_ready,
        'remote_changes_allowed': False,
        'detail_count': len(missing_settings),
    }
